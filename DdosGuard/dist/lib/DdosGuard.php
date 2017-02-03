<?php
namespace sb\DdosGuard;


class DdosGuard
{
    /**
     * Имя файла где хранится ствтус
     */
    const STATUS_FILE_NAME = 'ddos-guard.status.dat';

    /**
     * Кооманда iptables
     */
    const IPTABLES_COMMAND = '/sbin/iptables';

    public $config = [];

    public $status = [];

    public $Log;

    public $dirPath;

    function __construct($dirPath)
    {
        $this->dirPath = $dirPath;

        $this->statusFileName = $this->dirPath . '/' . self::STATUS_FILE_NAME;

        if($this->readStatus() === false)
        {
            $this->status['status'] = 0;
            $this->status['logs'] = [];
        }
    }

    /**
     * Загружает конфиг в объект и проверяет ваоидность
     *
     * @param $config
     *
     * @throws \Exception
     */
    function setConfig($config)
    {
        $this->config = array_merge(['disabled'=>false], $config);

        foreach($this->config['logs'] as &$log)
        {
            // Проверяем наличие файла парсера строки лога
            str_replace('.php', '', $log['rowHandler']);
            $log['handlerFilePath'] = $this->dirPath . '/handlers/' . $log['rowHandler'] . '.php';

            if (!file_exists($log['handlerFilePath']))
                throw new \Exception('Parameter rowHandler must much with file in directory handlers/. Change its in config file');

            // Проверяем доступность iptables и заполненость порта
            if (@$log['iptables'])
            {
                if (!$this->checkIptablesPermission())
                    throw new \Exception('service iptables is not instaled or permission denied. Change user for execution ddos.php');

                if (empty(@$log['iptables']['port']))
                    throw new \Exception('Parameter iptables.port is not set');
            }

            // Пока отключенно блокировку в .htacceess
            $log['htaccess'] = null;
        }
    }

    /**
     * Добавляет строку в лог
     *
     * @param $text
     */
    function log($text)
    {
        if ($this->Log)
            $this->Log->add($text);

        echo  $text . PHP_EOL;
    }

    /**
     * Проверяет доступность iptables
     *
     * @return bool
     */
    function checkIptablesPermission()
    {
        $output = [];
        $return = null;

        exec(self::IPTABLES_COMMAND . ' -L 2>/dev/null', $output, $return);

        if($return)
            return false;

        return true;
    }


    /**
     * Сохраняет в файл $this->status
     *
     */
    function saveStatus()
    {
        $this->status['lastSaveTime'] = time();

        $content = $this->status['status'] . ' ' . $this->status['lastSaveTime'] . PHP_EOL;

        foreach($this->status['logs'] as $id => $log)
        {
            $content .= "[$id]" . PHP_EOL;

            $content .= $log['lastRowTime'] . PHP_EOL;

            foreach($log['ip'] as $ip => $item)
            {
                $content .= $item['time'] . ' ' . $ip . ' ' . $item['estimate'] . PHP_EOL;
            }
        }

        file_put_contents($this->statusFileName, $content);
    }

    function resetStatus()
    {
        $this->status['status'] = 0;
        $this->saveStatus();
    }


    /**
     * Читает файл статуса в $this->status
     *
     * @return bool
     */
    function readStatus()
    {
        $this->status = [];

        $content = [];

        if(file_exists($this->statusFileName))
            $content = file($this->statusFileName);

        if(!$content)
            return false;

        $row = trim(array_shift($content));

        $row = explode(' ', $row);

        $this->status['status'] = (int)$row[0];
        $this->status['lastSaveTime'] = (int)$row[1];

        $log = [];
        $id = '';
        foreach($content as $row)
        {
            $row = trim($row);

            if(mb_strpos($row, '[') === 0)
            {
                if($log)
                {
                    $this->status['logs'][$id] = $log;
                }

                $log = [];
                $id = Helper::parseTextIntoChars($row, ['[', ']']);
                $log['id'] = $id;
            }
            else
            {
                $row = explode(' ', $row);
                if(count($row) == 1)
                {
                    $log['lastRowTime'] = (int)$row[0];
                }
                else
                {
                    $ip = $row[1];
                    $log['ip'][$ip]['time'] = $row[0];
                    $log['ip'][$ip]['ip'] = $ip;
                    $log['ip'][$ip]['estimate'] = $row[2];
                }
            }
        }

        if($log)
        {
            $this->status['logs'][$id] = $log;
        }
    }

    /**
     * Выполняет чтение и анализ все файлов лога
     *
     * @return bool
     */
    function run()
    {
        if($this->status['status'] != 0)
        {
            return false;
        }

        $this->status['status'] = getmypid();
        $this->status['lastSaveTime'] = time();

        $this->saveStatus();

        $this->unlock();

        foreach($this->config['logs'] as $id => $log)
        {
            $LogReader = new LogReader($log['filePath'], $log['limit']);

            if(!empty($this->status['logs'][$id]['lastRowTime']))
                $LogReader->timeFrom = $this->status['logs'][$id]['lastRowTime'];

            $LogReader->handlerFilePath = $this->dirPath . '/handlers/' . $log['rowHandler'] . '.php';

            try
            {
                $ipList = $LogReader->read();

            }
            catch(\Exception $e)
            {
                $this->log("Error: {$e->getMessage()}");
            }

            foreach($ipList as $ip => $count)
            {
                $time = time();
                $estimate = $this->config['estimate'];

                $this->lockIp($id, $ip, $time, $estimate);
            }

            $this->status['logs'][$id]['lastRowTime'] = $LogReader->getLastRowTime();
            $this->saveStatus();
        }

        // Чистим файлы htaccess
        foreach($this->config['logs'] as $id => $log)
        {
            if(!empty($log['htaccess']))
                $this->clearDenyHtaccess($log['htaccess']);
        }

        $this->status['status'] = 0;
        $this->saveStatus();
    }

    /**
     * @param $id - ид лога из конфига, как правила домен сайта
     * @param $ip - блокируемый ip, либо массив
     * @param bool $time - unixtime блокировки
     * @param bool $estimate - на сколько секунд блокируем блокировки
     *
     * @throws \Exception
     */
    function lockIp($id, $ip, $time = false, $estimate = false)
    {
        $this->log("Lock $id {$ip} {$time} {$estimate}");

        if(empty($this->config['logs'][$id]))
            throw new \Exception('Log id "' . $id . '" does not exist');

        $logStatus = &$this->status['logs'][$id];
        $logConfig = &$this->config['logs'][$id];

        if($time === false)
            $time = time();

        if($estimate === false)
            $estimate = $logConfig['estimate'];

        if(!$this->config['disabled'] && !isset($logStatus['ip'][$ip]))
        {
            // Блокируем в iptables
            if(@$logConfig['iptables'])
                $this->iptablesInsert($ip, $logConfig['iptables']['port']);

            // Блокируем в htaccess
            if(!empty($logConfig['htaccess']))
                $this->htaccessLock($logConfig['htaccess'], $time, $ip, $estimate);
        }

        // Сохраняем в массив статуса
        $logStatus['ip'][$ip] = [
            'time'     => $time,
            'estimate' => $estimate,
        ];

        $this->saveStatus();
    }

    /**
     * Разблокирует ip
     *
     * @param $id - ид лога из конфига, как правила домен сайта
     * @param $ip - заблокированный ip
     *
     * @throws \Exception
     */
    function unlockIp($id, $ip)
    {
        $this->log("Unlock {$id} {$ip}");

        if(empty($this->config['logs'][$id]))
            throw new \Exception('Log id "' . $id . '" does not exist');

        $logStatus = &$this->status['logs'][$id];
        $logConfig = &$this->config['logs'][$id];

        if(isset($logStatus['ip'][$ip]))
        {
            // Удаляем запись из iptables
            if(@$logConfig['iptables'])
                $this->iptablesDelete($ip, $logConfig['iptables']['port']);

            // удаляем запись из htaccess
            if(!empty($logConfig['htaccess']))
                $this->htaccessUnlock($logConfig['htaccess'], $ip);

            unset($logStatus['ip'][$ip]);
            $this->saveStatus();
        }
    }

    /**
     * Блокирует ip в файле .htaccess
     *
     * @param $filePath
     * @param $time
     * @param $ip
     * @param $estimate
     *
     * @throws \Exception
     */
    function htaccessLock($filePath, $time, $ip, $estimate)
    {
        $data = file($filePath);

        if(!Helper::validateIp($ip))
            throw new \Exception('"' . $ip . '" - is not valid ip address');

        foreach($data as $key => $item)
        {
            $data[$key] = trim($item);
        }

        $data[] = "#DdosGuard {$time} {$ip} $estimate";
        $data[] = "deny from {$ip}";

        $this->log("add lock from {$filePath}: ". current($data));

        file_put_contents($filePath, implode(PHP_EOL, $data));
    }

    /**
     * Разблокирует ip в файле .haccess
     *
     * @param $filePath
     * @param $ip
     */
    function htaccessUnlock($filePath, $ip)
    {
        $data = file($filePath);

        $i = 0;
        while(1)
        {
            if(!array_key_exists($i, $data))
                break;

            $item = $data[$i];

            $data[$i] = trim($item);

            if(mb_strpos($item, '#DdosGuard') === 0)
            {
                $arItem = explode(' ', $item);

                array_shift($arItem);
                array_shift($arItem);

                $ip2 = array_shift($arItem);

                if($ip2 == $ip)
                {
                    $this->log("Delete lock from {$filePath}: {$data[$i+1]}");

                    unset($data[$i]);
                    $i++;
                    unset($data[$i]);
                }
            }

            $i++;
        }

        file_put_contents($filePath, implode(PHP_EOL, $data));
    }

    /**
     * Проверяет файл .htaccess, удаляет deny from <ip> с истекшим временем
     *
     * @param $filePath
     */
    function clearDenyHtaccess($filePath)
    {
        $data = file($filePath);

        $i = 0;
        while(1)
        {

            if(!array_key_exists($i, $data))
                break;

            $item = $data[$i];

            $data[$i] = trim($item);

            if(mb_strpos($item, '#DdosGuard') === 0)
            {
                $arItem = explode(' ', $item);

                array_shift($arItem);

                $time = array_shift($arItem);
                $ip = array_shift($arItem);
                $estimate = array_shift($arItem);

                if(time() >= ($time + $estimate))
                {
                    $this->log("Delete lock from {$filePath}: {$data[$i+1]}");
                    unset($data[$i]);
                    $i++;
                    unset($data[$i]);
                }
            }

            $i++;
        }

        file_put_contents($filePath, implode(PHP_EOL, $data));
    }

    /**
     * Проверяет истекшие блокировки
     */
    function unlock()
    {
        foreach($this->status['logs'] as $id => $log)
        {
            foreach($log['ip'] as $ip => $item)
            {
                if(time() > $item['time'] + $item['estimate'])
                {
                    $this->unlockIp($id, $ip);
                }
            }
        }
    }

    /**
     * Вставляет запись в iptables
     *
     * @param $ip
     * @param int $port
     *
     * @return array
     */
    function iptablesInsert($ip, $port = 80)
    {
        $command = self::IPTABLES_COMMAND . " -L INPUT -v -n | grep {$ip}";
        $res = exec($command);

        if(!$res)
        {
            $command = self::IPTABLES_COMMAND . " -A INPUT -p tcp -s {$ip} --dport {$port} -j DROP";
            $output = [];
            exec($command, $output);
            $this->log('Execute command: ' . $command);
        }

        return $output;
    }

    /**
     * Удаляет запсь из iptables
     *
     * @param $ip
     * @param int $port
     *
     * @return array
     */
    function iptablesDelete($ip, $port = 80)
    {
        $command = self::IPTABLES_COMMAND . " -L INPUT -v -n | grep {$ip}";
        $res = exec($command);

        if($res)
        {
            $command = self::IPTABLES_COMMAND . " -D INPUT -p tcp -s {$ip} --dport {$port} -j DROP";
            $output = [];
            exec($command, $output);
            $this->log('Execute command: ' . $command);
        }

        return $output;
    }
}