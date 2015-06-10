<?php  

class Token {
    protected $_tokenid;
    protected $_aeskey;
    protected $_counter;
    protected $_internalid;
    protected $_timeStarted;
    protected $_timer;
    protected $_sessioncounter;
    protected $_randomnum;
    protected $_lockCode;

    public function __construct() {
      $args = func_get_args();
      switch (count($args)) {
        case 1:
          if ($args[0] === true) {
            // why is this 12,16???
            //$this->setID($this->getRandHexString(rand(12,16)));
            $this->setID($this->getRandHexString(rand(12,12)));
            $this->setInternalID($this->getRandHexString(12));
            $this->setAESKey($this->getRandHexString(32));
            $this->setCounter(0);
            $this->setLockCode($this->getRandHexString(12));
          }
          break;
        case 5:
          for ($i = 0; $i < 5; $i++) {
            $args[$i] = $this->modhex2hex($args[$i]);
          }

          $this->setID($args[0]);
          $this->setInternalID($args[1]);
          $this->setAESKey($args[2]);
          $this->setCounter($args[3]);
          $this->setLockCode($args[4]);
          break;
        default:
          throw new Exception('Invalid number of parameters to Token object');
      }

      $this->replug();
    }

    protected function buildTicket() {
      $this->_sessioncounter++;
      if ($this->_sessioncounter > 255) {
        $this->_sessioncounter = 1;
      }

      $ticket = $this->getInternalID();
      $ticket .= $this->getCounter();
      $ticket .= $this->getTimer();
      $ticket .= $this->getSessionCounter();
      $ticket .= $this->getRandNum();
      $ticket .= $this->buildCRC($ticket);

      //$SESSION['errors'][] = "Ticket built: $ticket";

      return $ticket;
    }

    public function replug() {
      if ($this->_counter < 32767) {
        $this->_counter++;
      }
      $this->_sessioncounter = 0;
      $this->_randomnum = $this->getRandHexString(4);
      $this->_timeStarted = time();
      $this->_timer = rand(0, 16777215);
    }

    public function getTicket() {
      $unenc = $this->buildTicket();

      $ticket = $this->getID();
      $ticket .= $this->encryptTicket($unenc);

      $ticket = $this->hex2modhex($ticket);
      //print("your ticket is: \n");
      //print_r($ticket);
     $SESSION['errors'][] = "OTP: $ticket";

      return $ticket;
    }

    protected function hex2modhex($string) {
      return strtr($string, "0123456789abcdef", "cbdefghijklnrtuv");
    }

    protected function modhex2hex($string) {
      return strtr($string, "cbdefghijklnrtuv", "0123456789abcdef");
    }

    protected function encryptTicket($ticket) {
      $o = bin2hex(mcrypt_ecb(MCRYPT_RIJNDAEL_128,
        pack("H*",$this->getAESKey()),
        pack("H*",$ticket),
        MCRYPT_ENCRYPT));

      return $o;
    }

    protected function buildCRC($ticketData) {
      $ticketData = str_split($ticketData, 2);
      $buffer = array();

      foreach ($ticketData as $byte) {
        $buffer[] = chr(hexdec($byte));
      }
      
      $m_crc=0x5af0;
    
      for($bpos=0; $bpos<14; $bpos++) {
        $m_crc ^= ord($buffer[$bpos]);

        for ($i=0; $i<8; $i++) {
          $j=$m_crc & 1;
          $m_crc >>= 1;
          if ($j) $m_crc ^= 0x8408;
        }
      }
      $crchex = str_pad(dechex($m_crc),4,"0",STR_PAD_LEFT);
      $crchex = substr($crchex,2,2) . substr($crchex,0,2);

      return $crchex;
        }


    protected function getRandHexString($length) {
      $str = "";

      for ($i = 0; $i < $length; $i++) {
        $str .= dechex(rand(0,15));
      }

      return $str;
    }

    public function setID($tokenid) {
      if (!preg_match("/^[0-9a-f]{12,16}$/", $tokenid)) {
        throw new Exception('Invalid Token ID');
      }
      $this->_tokenid = $tokenid;
    }

    public function getID() {
      return $this->_tokenid;
    }

    public function setInternalID($iid) {
      if (!preg_match("/^[0-9a-f]{12}$/", $iid)) {
        throw new Exception('Invalid Internal ID');
      }
      $this->_internalid = $iid;
    }

    public function getInternalID() {
      return $this->_internalid;
    }

    public function setAESKey($key) {
      if (!preg_match("/^[0-9a-f]{32}$/", $key)) {
        throw new Exception('Invalid AES key');
      }
      $this->_aeskey = $key;
    }

    public function getAESKey() {
      return $this->_aeskey;
    }

    public function setCounter($counter) {
      if ($counter === NULL) {
        $counter = 0;
      }
      if ($counter < 0 || $counter > 32767) {
        throw new Exception('Counter out of range');
      }
      $this->_counter = $counter;
    }

    public function getCounter() {
      $cnt = $this->_counter;

      $cnt = str_pad(dechex($cnt),4,"0",STR_PAD_LEFT);
      $cnt = substr($cnt,2,2) . substr($cnt,0,2);

      return $cnt;
    }

    public function getSessionCounter() {
      $cnt = $this->_sessioncounter;

      $cnt = str_pad(dechex($cnt),2,"0",STR_PAD_LEFT);

      return $cnt;
    }

    public function getRandNum() {
      return $this->_randomnum;
    }

    public function getTimer() {
      $curTime = time();
      $ticks = (($curTime - $this->_timeStarted) / 8);
      $this->_timer += $ticks;

      if ($this->_timer > 16777215) {
        $this->_timer -= 16777215;
      }

      $this->_timeStarted = $curTime;

      $timer = str_pad(dechex((int)$this->_timer),6,"0",STR_PAD_LEFT);
      $timer = substr($timer,4,2) . substr($timer,2,2) . substr($timer,0,2);

      return $timer;
    }

    public function setLockCode($code) {
      if(!preg_match("/^[0-9a-f]{12}$/", $code)) {
        throw new Exception('Invalid Lock Code');
      }
      $this->_lockCode = $code;
    }

    public function getLockCode() {
      return $this->_lockCode;
    }
  }
?>
