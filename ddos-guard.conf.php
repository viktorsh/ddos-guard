<?php

return [
    'logFilePath' => '/var/log/ddos-guard.log',
    'estimate' => 500,
    'disabled'  => true,
    'logs' => [
        'alsi.kz' => [
            'filePath' => '/var/log/alsi_access_log-20161225',
            'limit' => [[100, 180]], // 100 раз за 180 секунд
            //'htaccess'=> __DIR__ . '/.htaccess',
            'useIptables'=> true,
            'rowHandler' => 'row_handler_default'

        ]
    ]
];
