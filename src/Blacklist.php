<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Monolog\Level;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

class Blacklist
{
    private $blacklist = [];
    public Logger $logger;

    public function __construct(?array $blacklist)
    {
        $this->logger = new Logger('blacklist');



        $this->blacklist = $blacklist;
    }

    public function setupLogger(): void
    {
        $log = realpath(__DIR__ . '/../logs/') . '/blacklist.log';

        $streamHandler = new StreamHandler($log);
        $streamHandler->setFormatter(new \Monolog\Formatter\LineFormatter(null, null, true, true));
        $this->logger->pushHandler($streamHandler);
        $handler = new StreamHandler('php://stdout');
        $handler->setFormatter(new \Monolog\Formatter\LineFormatter(null, null, true, true));
        $this->logger->pushHandler($handler);


        $this->logger->info('Blacklist initialized');
    }
    public function validIP(string $ip): bool
    {
        $valid = inet_pton($ip) !== false;

        if (!$valid) {
            throw new InvalidArgumentException("$ip invalid IP address");
        }

        return $valid;
    }

    public function isIpv4($ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    public function isIpv6($ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    public function reverseIPV4($ip): string
    {
        if (!$this->isIpv4($ip)) {
            throw new InvalidArgumentException("Invalid IPv4 address");
        }

        return implode('.', array_reverse(explode('.', $ip)));
    }

    public  function expandIpv6(string $ip): string
    {
        $hex = unpack("H*hex", inet_pton($ip));

        return substr(preg_replace("/([A-f0-9]{4})/", "$1:", $hex['hex']), 0, -1);
    }

    public function reverseIPV6(string $ip): string
    {
        if (!$this->isIpv6($ip)) {
            throw new InvalidArgumentException("Invalid IPv6 address");
        }

        $ip = $this->expandIpv6($ip);

        $ip = str_replace(":", "", $ip);

        $ip = str_split($ip);

        $ip = implode(".", array_reverse($ip));

        return $ip;
    }

    public function reverseIP($ip): string
    {
        if ($this->isIpv4($ip)) {
            return $this->reverseIPV4($ip);
        }

        return $this->reverseIPV6($ip);
    }

    public  function isBlacklisted($ip): array
    {
        $this->validIP($ip);

        $rip = $this->reverseIP($ip);

        for ($i = 0; $i < count($this->blacklist); $i++) {
            if (checkdnsrr($rip . "." . $this->blacklist[$i], "A")) {
                return ['blacklisted' => true, 'blacklist' => $this->blacklist[$i]];
            }
        }

        return  ['blacklisted' => false, 'blacklist' => null];
    }
}

$blacklist = new Blacklist(["all.s5h.net", "sbl.spamhaus.org"]);

foreach (
    [
        "52.169.25.10",
        "::1",
        "2606:4700:3030::ac43:83e1",
        "2603:1010:200::32c",
        "181.215.196.125",
        "179.61.242.120",
        "162.241.92.55"
    ] as $ip
) {
    $result = $blacklist->isBlacklisted($ip);

    if ($result['blacklisted']) {
        $blacklistName = $result['blacklist'];
        $blacklist->logger->warning("$ip is blacklisted on $blacklistName");
    } else {
        $blacklist->logger->info("$ip is not blacklisted");
    }
}
