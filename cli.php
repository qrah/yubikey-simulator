<?php
  /**
   * @name YubiKey Simulator v0.9
   * @author Sam Stelfox
   * @license MIT
   */ 

  include "class.php";


$help = "
############################
###### Help ###############

action =
  create
  save
     tokenname=nameoftoken
  reset
  genrand
  getticket
  replug
  deletekey (deletes saved token)
     key=nameoftoken
  restoresaved
  clearsaved
  
tokenid
privid
aeskey
####################
to create a new one:
 ./yt action=genrand
 ./yt action=save tokenname=[username]

to switch token:
 ./yt action=restoresaved key=[username]
";
print($help);
parse_str(implode('&', array_slice($argv, 1)), $_GET);

//session_start();
$SESSION = unserialize(file_get_contents('yubikeys.bin'));
  ob_start();

  if (!isset($SESSION['errors'])) {
    $SESSION['errors'] = array();
    print_r($SESSION['errors']);
  }
  if (!isset($SESSION['savedtokens'])) {
    $SESSION['savedtokens'] = array();
  }

  if (isset($_GET['action']) && !empty($_GET['action'])) {
    switch($_GET['action']) {
      case "create":
        $validinput = true;
        if (!(isset($_GET['tokenid']) && !empty($_GET['tokenid']))) {
          $SESSION['errors'][] = 'Missing Token ID!';
          $validinput = false;
        }
        if (!(isset($_GET['privid']) && !empty($_GET['privid']))) {
          $SESSION['errors'][] = 'Missing Internal ID!';
          $validinput = false;
        }
        if (!(isset($_GET['aeskey']) && !empty($_GET['aeskey']))) {
          $SESSION['errors'][] = 'Missing AES Key!';
          $validinput = false;
        }
        if ($validinput) {
          $SESSION['token'] = new Token($_GET['tokenid'],
            $_GET['privid'],
            $_GET['aeskey'],
            $_GET['counter'],
            $_GET['lockcode']
          );
          $SESSION['errors'][] = 'Key imported from form.';
        } else {
          $SESSION['errors'][] = 'You need to fill in all of the required form data.';
        }

        break;
      case "save":
        if (isset($_GET['tokenname'])) {
          $SESSION['savedtokens'][$_GET['tokenname']] = $SESSION['token'];
          $SESSION['errors'][] = 'Token saved as ' . $_GET['tokenname'];
        }
        break;
      case "reset":
        if (isset($SESSION['token'])) {
          unset($SESSION['token']);
          $SESSION['errors'][] = 'Virtual Token Reset';
        } else {
          $SESSION['errors'][] = 'No Virtual Token to Reset';
        }
        break;
      case "genrand":
        $SESSION['token'] = new Token(true);
        $SESSION['errors'][] = 'Initialized Random Token';
        break;
      case "getticket":
        if (isset($SESSION['token']) && !empty($SESSION['token'])) {
          $SESSION['token']->getTicket();
echo ("
########################################################
######### Your ticket  ######## ########################
");
echo ('ticket=' . $SESSION['token']->getTicket());
echo ("
"); 


        } else {
          $SESSION['errors'][] = 'No token information available to build a ticket.';
        }
        break;
      case "replug":
        if (isset($SESSION['token']) && !empty($SESSION['token'])) {
          $SESSION['token']->replug();
          $SESSION['errors'][] = 'Unplugged and plugged back in token.';
        } else {
          $SESSION['errors'][] = 'No token to unplug/replug.';
        }
        break;
      case "deletekey":
        print_r($SESSION['savedtokens']);
        if (isset($SESSION['savedtokens'][$_GET['key']])) {
          unset($SESSION['savedtokens'][$_GET['key']]);
          $SESSION['errors'][] = 'Key Deleted.';
        } else {
          $SESSION['errors'][] = 'Invalid key. Can not delete.';
        }
        break;
      case "restoresaved":
        if (isset($SESSION['savedtokens'][$_GET['key']])) {
          $SESSION['token'] = $SESSION['savedtokens'][$_GET['key']];
          $SESSION['errors'][] = 'Key Restored.';
        } else {
          $SESSION['errors'][] = 'Invalid key. Can not restore.';
        }
        break;
      case "clearsaved":
        $SESSION['savedtokens'] = array();
        break;
      default:
        $SESSION['errors'][] = 'Unknown or Invalid action requested';
      }
  }

  if (!empty($SESSION['errors'])) {
    echo '<div id="messages"><fieldset><legend>Messages</legend><p><ul>';
    foreach ($SESSION['errors'] as $error) {
      echo "<li>$error</li>";
    }
    echo '</ul></fieldset></div>';
    unset($SESSION['errors']);
  }

  if (isset($SESSION['savedtokens'])) {
echo ("
########################################################
######### Saved Tokens ######## ########################
      name         |        id \n");
    foreach ($SESSION['savedtokens'] as $name=>$tkn) {
echo $name . '           ' . $tkn->getID() . " \n"  ;
echo "yubiserver-admin --yubikey --add  {$name} {$tkn->getID_modhex()} {$tkn->getInternalID()} {$tkn->getAESKey()} \n\n";

 
    
    }
  }
  
  if (count($SESSION['savedtokens']) > 0) {
   // echo "<p><a href='?action=clearsaved' />Clear all saved tokens</a></p>";
  }
  
  if (isset($SESSION['token']) && !empty($SESSION['token'])) {
    echo '';
  }
  
  if (isset($SESSION['token']) && !empty($SESSION['token'])) {
    echo "
########################################################
######### Internal Token Values ########################
Token ID:          {$SESSION['token']->getID()}
Token ID (modhex): {$SESSION['token']->getID_modhex()}
AES Key:           {$SESSION['token']->getAESKey()}
Internal ID:       {$SESSION['token']->getInternalID()}
Usage Counter:     {$SESSION['token']->getCounter()}
Session Counter:   {$SESSION['token']->getSessionCounter()}
Random Number:     {$SESSION['token']->getRandNum()}
Timestamp:         {$SESSION['token']->getTimer()}
Lock Code:         {$SESSION['token']->getLockCode()}

to import:
yubiserver-admin --yubikey --add  [username] {$SESSION['token']->getID_modhex()} {$SESSION['token']->getInternalID()} {$SESSION['token']->getAESKey()}

";
  }
?>

<?php
  //print_r($SESSION);
  file_put_contents('yubikeys.bin', serialize($SESSION));

  ob_end_flush();
?>
