<?php
namespace sb\DdosGuard;

// Подключаем автозагрузчик классов
spl_autoload_register(function ($class)
{
    if (($pos = strpos($class, __NAMESPACE__.'\\')) !== false)
    {

        $subNamespace = substr($class, strlen(__NAMESPACE__));

        $arClass = explode('\\', trim($subNamespace, '\\'));
        $className = array_pop($arClass);

        $dir = '';

        if ($arClass)
            $dir = implode(DIRECTORY_SEPARATOR, $arClass) . DIRECTORY_SEPARATOR;

        $filePath = __DIR__ . '/' .'lib/' . $dir . $className . '.php';

        if (file_exists($filePath))
            include $filePath;
    }
});