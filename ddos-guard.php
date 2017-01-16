#!/usr/bin/env php
<?php

$config = require_once ('ddos-guard.conf.php');
$config['dirPath'] = __DIR__;

include_once ($config['dirPath'] . '/DdosGuard/dist/__autoload.php');

if ($config['logFilePath'])
    $Log = new \sb\DdosGuard\FileOutput($config['logFilePath']);

try
{
    $Ddos = new \sb\DdosGuard\DdosGuard($config);

    $Ddos->Log = $Log;

    $Log->add('start');

    if ($Ddos->run() === false)
    {
        if ($Log)
            $Log->add('Occupied by another process');

        echo 'Occupied by another process' . PHP_EOL;
    }

    $Log->add('finish');
}
catch(Exception $e)
{
    if ($Log)
        $Log->add('Error: ' . $e->getMessage());

    echo 'Error: ' . $e->getMessage() . PHP_EOL;
}



