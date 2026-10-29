<?php
// Run ONLY on the OPNsense console as root. Default mode is read-only.
require_once('script/load_phalcon.php');
use OPNsense\Core\Config;

function stop_now($message) {
    throw new RuntimeException($message);
}

$apply = in_array('--apply', $argv, true);
$keepSsh = in_array('--keep-existing-ssh', $argv, true);
$ntpOnly = in_array('--ntp-only', $argv, true);
$addSsh = in_array('--add-ssh', $argv, true);
$manager = null;
try {
    if (($keepSsh && $ntpOnly) || ($addSsh && $ntpOnly)) {
        stop_now('La modalita --ntp-only non puo essere combinata con opzioni SSH.');
    }
    $manager = Config::getInstance();
    if ($apply) {
        $manager->lock();
    }
    $xml = $manager->object();
    $interfaces = [];
    foreach ($xml->interfaces->children() as $name => $entry) {
        $device = trim((string)$entry->if);
        if (in_array($device, ['vlan0.40', 'vlan0.99'], true)) {
            if (isset($interfaces[$device])) {
                stop_now('Interfaccia ambigua: ' . $device);
            }
            $interfaces[$device] = $name;
        }
    }
    if (count($interfaces) !== 2) {
        stop_now('Non trovate entrambe le interfacce vlan0.40 e vlan0.99. Nessuna modifica.');
    }
    echo "VERSION=4_ADD_NTP_AND_AUTHORIZED_SSH\n";
    if (!isset($xml->filter)) {
        stop_now('Sezione filter legacy assente. Nessuna modifica.');
    }
    $hosts = ['vlan0.40' => '10.0.40.13', 'vlan0.99' => '10.0.99.14'];
    $selected = [];
    $sshPersistent = false;
    foreach ($xml->filter->rule as $rule) {
        if (isset($rule->disabled)) {
            continue;
        }
        $iface = trim((string)$rule->interface);
        $proto = strtolower(trim((string)$rule->protocol));
        $port = strtolower(trim((string)$rule->destination->port));
        $type = strtolower(trim((string)$rule->type));
        $direction = strtolower(trim((string)$rule->direction));
        if ($type !== 'pass' || isset($rule->floating) ||
            !in_array($direction, ['', 'in'], true)) {
            continue;
        }
        if ($iface === $interfaces['vlan0.40'] && $proto === 'tcp' &&
            in_array($port, ['22', 'ssh'], true) &&
            trim((string)$rule->source->address) === '10.0.40.13' &&
            trim((string)$rule->destination->address) === '10.0.99.14' &&
            !isset($rule->source->not) && !isset($rule->destination->not)) {
            $sshPersistent = true;
        }
        foreach ($interfaces as $device => $logical) {
            if ($iface === $logical && $proto === 'udp' &&
                in_array($port, ['123', 'ntp'], true) &&
                trim((string)$rule->ipprotocol) === 'inet' &&
                trim((string)$rule->source->address) === $hosts[$device] &&
                isset($rule->destination->any) &&
                !isset($rule->source->not) && !isset($rule->destination->not)) {
                $selected[$device][] = $rule;
            }
        }
    }
    foreach ($interfaces as $device => $logical) {
        if (count($selected[$device] ?? []) > 1) {
            stop_now('Piu regole NTP dedicate equivalenti su ' . $device . '. Verificare prima di modificare.');
        }
        printf("NTP %s (%s): %s -> any UDP 123: %s\n", $device, $logical, $hosts[$device], empty($selected[$device]) ? 'DA AGGIUNGERE' : 'GIA PRESENTE');
    }
    echo 'SSH persistente 10.0.40.13 -> 10.0.99.14:22: ' . ($sshPersistent ? 'presente' : 'assente') . "\n";
    if ($ntpOnly) {
        echo "MODALITA=NTP_ONLY. Nessuna regola SSH viene aggiunta o modificata.\n";
    }
    if ($addSsh) {
        echo 'SSH 10.0.40.13 -> 10.0.99.14 TCP 22: ' . ($sshPersistent ? 'GIA PRESENTE' : 'DA AGGIUNGERE IN MODO PERSISTENTE') . "\n";
    }
    if (!$apply) {
        echo "CHECK_OK. Solo anteprima: configurazione non salvata.\n";
        exit(0);
    }
    if (!$sshPersistent && !$keepSsh && !$ntpOnly && !$addSsh) {
        stop_now('Scegliere --add-ssh per aggiungere SSH, --ntp-only per solo NTP, oppure --keep-existing-ssh per preservare un permesso attivo.');
    }
    if (!$sshPersistent && $keepSsh && !$addSsh) {
        $lines = [];
        $code = 0;
        exec('/sbin/pfctl -sr 2>&1', $lines, $code);
        $found = false;
        foreach ($lines as $line) {
            if (preg_match('/^pass in quick on vlan0\.40 inet proto tcp from 10\.0\.40\.13 to 10\.0\.99\.14 port = (?:ssh|22)(?:\s|$)/', $line)) {
                $found = true;
            }
        }
        if ($code !== 0 || !$found) {
            stop_now('Regola SSH attiva attesa non trovata: nessun nuovo accesso viene creato.');
        }
    }
    $backup = '/conf/gns3-before-ntp-' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(3)) . '.xml';
    if (!copy('/conf/config.xml', $backup) || !chmod($backup, 0600)) {
        stop_now('Backup non riuscito. Nessun salvataggio.');
    }
    echo "BACKUP=$backup\n";
    foreach ($interfaces as $device => $logical) {
        if (!empty($selected[$device])) {
            continue;
        }
        $new = $xml->filter->addChild('rule');
        $new->addChild('type', 'pass');
        $new->addChild('interface', $logical);
        $new->addChild('ipprotocol', 'inet');
        $new->addChild('protocol', 'udp');
        $new->addChild('direction', 'in');
        $new->addChild('log', '1');
        $source = $new->addChild('source');
        $source->addChild('address', $hosts[$device]);
        $destination = $new->addChild('destination');
        $destination->addChild('any');
        $destination->addChild('port', '123');
        $new->addChild('descr', 'GNS3 NTP UDP 123 for host ' . $hosts[$device]);
        $node = dom_import_simplexml($new);
        $firstRule = dom_import_simplexml($xml->filter->rule[0]);
        if ($node !== $firstRule) {
            $node->parentNode->insertBefore($node, $firstRule);
        }
    }
    if (!$sshPersistent && ($keepSsh || $addSsh)) {
        $new = $xml->filter->addChild('rule');
        $new->addChild('type', 'pass');
        $new->addChild('interface', $interfaces['vlan0.40']);
        $new->addChild('ipprotocol', 'inet');
        $new->addChild('protocol', 'tcp');
        $new->addChild('direction', 'in');
        $new->addChild('log', '1');
        $source = $new->addChild('source');
        $source->addChild('address', '10.0.40.13');
        $destination = $new->addChild('destination');
        $destination->addChild('address', '10.0.99.14');
        $destination->addChild('port', '22');
        $new->addChild('descr', 'GNS3 authorized Windows-HR to Wazuh SSH access');
        $node = dom_import_simplexml($new);
        $firstRule = dom_import_simplexml($xml->filter->rule[0]);
        if ($node !== $firstRule) {
            $node->parentNode->insertBefore($node, $firstRule);
        }
    }
    if (!$manager->isValid()) {
        stop_now('Modello configurazione non valido. Nessun salvataggio.');
    }
    $manager->save(['description' => $ntpOnly ? 'GNS3: add host-specific NTP UDP rules only' : 'GNS3: host-specific NTP UDP and authorized HR to Wazuh SSH']);
    $manager->unlock();
    $disk = simplexml_load_file('/conf/config.xml');
    if ($disk === false) {
        stop_now('Verifica XML dopo salvataggio fallita. Ripristinare il backup dalla console.');
    }
    echo "CONFIG_SAVED. Ora applicare con configctl filter reload e verificare le regole attive.\n";
} catch (Throwable $error) {
    if ($manager !== null && $apply) {
        $manager->unlock();
    }
    fwrite(STDERR, 'ERRORE: ' . $error->getMessage() . "\n");
    exit(1);
}
