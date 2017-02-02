<?php
namespace sb\DdosGuard;


/**
 * Created by PhpStorm.
 * User: viktor
 * Date: 10.01.2017
 * Time: 15:10
 */

class Row
{
    public $row;

    public $ip;
    public $unixtime;
    public $timezone;
    public $request;
    public $status;
    public $body_bytes_sent;
    public $http_referer;
    public $http_user_agent;
    public $http_x_forwarded_for;

    function __construct($row)
    {
        $this->row = $row;
    }

    function parse($handlerFunction)
    {
        if (!$this->row)
            throw new \Exception('Property "row" is not set');

        $handlerFunction($this);

        if (!$this->ip)
            throw new \Exception('Property "ip" is not defined');

        if (!ip2long($this->ip))
            throw new \Exception('Property "ip" is incorrect');

        if (!$this->status)
            throw new \Exception('Property "status" is not defined');
        
        if (!is_numeric($this->status))
            throw new \Exception('Property "status" is incorrect');

        if (!$this->unixtime)
            throw new \Exception('Property "unixtime" is not defined');
    }
}