<?php
namespace sb\DdosGuard;


class DdosGuard
{
    const STATUS_FILE_NAME = 'ddos-guard.status.dat';

    public $config = [];

    public $status = [];

    public $Log;


    function __construct($config)
    {
        $this->config = array_merge(['disabled'=>false], $config);

        foreach($this->config['logs'] as $log)
        {

            // Проверяем наличие файла парсера строки лога
            str_replace('.php', '', $log['rowHandler']);
            $log['handlerFilePath'] = $this->config['dirPath'] . '/handlers/' . $log['rowHandler'] . '.php';

            if (!file_exists($log['handlerFilePath']))
                throw new \Exception('Parameter rowHandler must much with file in directory handlers/. Change its in config file');

            // Проверяем доступность iptables
            if ($log['useIptables'] && !$this->checkIptablesPermission())
                throw new \Exception('service iptables is not instaled or permission denied. Change user for execution ddos.php');
        }

        $this->statusFileName = $config['dirPath'] . '/' . self::STATUS_FILE_NAME;

        if($this->readStatus() === false)
        {
            $this->status['status'] = 0;
            $this->status['logs'] = [];
        }
    }

    function log($text)
    {
        if ($this->Log)
            $this->Log->add($text);

        echo  $text . PHP_EOL;
    }


    function checkIptablesPermission()
    {
        $output = [];
        $return = null;

        exec('iptables -L 2>/dev/null', $output, $return);

        if($return)
            return false;

        return true;
    }


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

            $LogReader->handlerFilePath = $this->config['dirPath'] . '/handlers/' . $log['rowHandler'] . '.php';

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
            if($logConfig['useIptables'])
                $this->iptablesInsert($ip, 80);

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
            if($logConfig['useIptables'])
                $this->iptablesDelete($ip, 80);

            // удаляем запись из htaccess
            if(!empty($logConfig['htaccess']))
                $this->htaccessUnlock($logConfig['htaccess'], $ip);

            unset($logStatus['ip'][$ip]);
            $this->saveStatus();
        }
    }

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

    function iptablesInsert($ip, $port = 80)
    {
        $command = "iptables -L INPUT -v -n | grep {$ip}";
        $res = exec($command);

        if(!$res)
        {
            $command = "iptables -A INPUT -p tcp -s {$ip} --dport {$port} -j DROP";
            $output = [];
            exec($command, $output);
            $this->log('Execute command: ' . $command);
        }

        return $output;
    }

    function iptablesDelete($ip, $port = 80)
    {
        $command = "iptables -L INPUT -v -n | grep {$ip}";
        $res = exec($command);

        if($res)
        {
            $command = "iptables -D INPUT -p tcp -s {$ip} --dport {$port} -j DROP";
            $output = [];
            exec($command, $output);
            $this->log('Execute command: ' . $command);
        }

        return $output;
    }
}

?>
