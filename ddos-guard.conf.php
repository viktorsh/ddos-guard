<?php
return [
    'logFilePath' => '/var/log/ddos-guard.log',         // *Файл лога работы скрипта
    'estimate' => 500,                                  // *время в секундах на которое блокируется ip адрес
    'disabled'  => true,                                // *Запрет блокировки ip адресов, только пищет в лог и в файл ddos-guard.status.dat
    'logs' => [                                         // Масссив обработчиков логов
        'alsi.kz' => [
            'filePath' => '/var/log/alsi_access_log-20161225',          // * Путь до файла логов для парсинга и анализа
            'limit' => [[100, 180]],                                    // * массиа лимиты блокировок. первый количество записей в логи, второй за какое время
            //'htaccess'=> __DIR__ . '/.htaccess',                      // путь к htaacess файлу в котором будем блокировать ip через deny from
            'useIptables'=> true,                                       // Флаг использования файрвола iptables для блокировки ip по порту
            'rowHandler' => 'row_handler_default'                       // * имя файла в каталоге handlers, который парсит строку из файла логов
        ]
    ]
];
