#!/usr/bin/env php
<?php

$config = require_once ('ddos-guard.conf.php');
$dirPath = __DIR__;

include_once ($dirPath . '/DdosGuard/dist/__autoload.php');

try
{
    $Ddos = new \sb\DdosGuard\DdosGuard($dirPath);

    if (@$argv[1] == 'status')
    {
        if ($Ddos->status['status'])
        {
            echo 'status:'. chr(9) . ' processing...' . PHP_EOL;
            echo 'pid:' . chr(9) . chr(9) . $Ddos->status['status'] . PHP_EOL;
            echo 'last saved:' . chr(9) . date('d.m.Y H:i:s', $Ddos->status['lastSaveTime']) . PHP_EOL;
        }
        else
        {
            echo 'status:'. chr(9) . ' finished...' . PHP_EOL;
            echo 'date:' . chr(9) . date('d.m.Y H:i:s', $Ddos->status['lastSaveTime']) . PHP_EOL;
        }

        foreach($Ddos->status['logs'] as $item)
        {
            if (!@$item['ip'])
                continue;

            echo PHP_EOL . $item['id'] . PHP_EOL;
            foreach($item['ip'] as $ip)
            {
                echo $ip['ip'] . chr(9) . date('d.m.Y H:i:s', $ip['time']). chr(9) . date('d.m.Y H:i:s', $ip['time'] + $ip['estimate']) . PHP_EOL;
            }
        }

        return;
    }
    elseif(@$argv[1] == 'reset')
    {
        $Ddos->resetStatus();
        return;
    }

    if ($config['logFilePath'])
        $Log = new \sb\DdosGuard\FileOutput($config['logFilePath']);

    $Ddos->setConfig($config);

    $Ddos->Log = $Log;

    $Log->add('start');

    if ($Ddos->run() === false)
    {
        if ($Log)
            $Log->add('Occupied by another process');

        echo 'Occupied by another process ' . PHP_EOL;
    }

    $Log->add('finish');
}
catch(Exception $e)
{
    if ($Log)
        $Log->add('Error: ' . $e->getMessage());

    echo 'Error: ' . $e->getMessage() . PHP_EOL;
}
