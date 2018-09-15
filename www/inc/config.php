<?

	$host = "localhost";
	$dbase = "ipa";
	$dblogin = "ipauser";
	$dbpass = "ipauser";

 $f = mysql_connect("$host","$dblogin","$dbpass") or die("Error connect");
 $db = mysql_select_db("$dbase") or die("Error select base $dbase");




function sql_open($query){

 $f = mysql_connect("$host","$dblogin","$dbpass") or die("Error connect");
 $db = mysql_select_db("$dbase") or die("Error select base");
 $result = mysql_query("$query") or die("Error query $query");
 return $result;
}

$traftype = array('0' => "Безлимитный",
                  '1' => "Входящий",
                  '2' => "Исходящий",
                  '3' => "Вход+Исход");

$status = array('0' => "<font color=#0000ff>Рабочий</font>",
                '1' => "<font color=#ff0000>Заблокирован</font>",
                '2' => "Error!!!");

$blockedname=array('root','admin','bin','daemon',
                   'adm','mail','news','uucp',
                   'operator','ftp','www');

$month = array(
               '01' => 'Январь', '02' => 'Февраль','03' => 'Март',
               '04' => 'Апрель', '05' => 'Май',    '06' => 'Июнь',
               '07' => 'Июль',   '08' => 'Август', '09' => 'Сентябрь',
               '10' => 'Октябрь','11' => 'Ноябрь', '12' => 'Декабрь');


$monthy = array('00' => "00",
                '01' => "Января", '02' => "Февраля",'03' => "Марта",
                '04' => "Апреля", '05' => "Мая",    '06' => "Июня",
                '07' => "Июля",   '08' => "Августа",'09' => "Сентября",
                '10' => "Октября",'11' => "Ноября", '12' => "Декабря");

$wdays = array( 'Воскресенье',
                'Понедельник',
                'Вторник',
                'Среда',
                'Четверг',
                'Пятница',
                'Суббота',
                'Празничный' );

$mdays = array('1'=>"Пн",'2'=>"Вт",'3'=>"Ср",'4'=>"Чт",'5'=>"Пт",'6'=>"Сб",'7'=>"Вс");


$grptype = array('0' => "Безлимитный",
                 '1' => "Почасовой",
                 '2' => "Почасовой + Траффик",
                 '3' => "Траффик",
                 '4' => "Посуточный");

$grptraf_type = array('0' => "Входящий",
                      '1' => "Суммарный",
                      '2' => "Больший",
                      '3' => "Исходящий",);


$mode_oper = array('0' => "R/O",
                   '1' => "R/W",
                   '2' => "Full Access");


function history_log($uname,$at){
  global $ouser;
  $dtime = date("Y-m-d H:m:i");
  $query = "INSERT INTO history (name,date,action,operator) VALUES ('$uname','$dtime','$at','$ouser')";
  $res = mysql_query("$query") or die("Error query <font color=\"RED\">$query</font>");
  return;
}


function print_date($d){

global $monthy;

   if ($d == 0){
#   echo "NA ";
   echo "";
   return;}
#  echo "$d  ";
# list ( $year,$month,$day) = split ("[/.-]", $d);
#   echo "$day $monthy[$month] $year";

if (ereg ("([0-9]{4})[/.-]([0-9]{1,2})[/.-]([0-9]{1,2})",$d,$t)) {
  list ($w,$year,$month,$day) = $t;
#   echo "$day  $month $year $w";
   echo "$day  $monthy[$month] $year г.";
#   echo "$t[3].$t[2].$t[1]";

#   echo "$monthy[$t] ";

}else{
   echo "<font color=\"RED\">$d<font> неверный формат";
}

# 2002-23-12
#   echo "$d ";
#   $t = substr($d,-2); # day
#   echo "$t ";
#   $t = substr($d,5,-3); # month
#   echo "$monthy[$t] ";
#   $t = substr($d,0,4);# year
#   echo "$t";
   return;
}

function print_datetime($d){

#$d ="1994-10-11 13:23:34";

global $monthy;

if ( ereg ("([0-9]{4})[/.-]([0-9]{1,2})[/.-]([0-9]{1,2})[ ]([0-9]{2})[:]([0-9]{2})[:]([0-9]{2})",$d,$t)) {
  list ($w,$year,$month,$day,$hour,$min,$sec) = $t;
   echo "$day $monthy[$month] $year г. $hour:$min:$sec";
}else{
   echo "<font color=\"RED\">$d<font> неверный формат";
}
   return;
}


function print_ip($ip){

#$ip = "102.123.102.3";

if(ereg("([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})",$ip,$t)){
    list ($w,$ip,$ip8,$ip16,$ip32) = $t;
  echo "$ip.$ip8.$ip16.$ip32";
}else
if(!isset($ip) || (isset($ip) && $ip == 0))
  echo "";
 else
#  echo "Invalid ip address format: <font color=\"RED\">$ip<font>";
  echo "<font color=\"RED\">$ip<font> неверный формат";
return;
}


function radusers(){
$argrp = array();
$row = 0;
$fp = fopen("/usr/local/etc/raddb/users","r");

while ($data = fgetcsv ($fp, 1000, ",")) {
   $num = count ($data);
#   print "<p> $num fields in line $row: <br>";
   $row++;
   for ($c=0; $c < $num; $c++) {
   $d = $data[$c];
   if( $d !=""){
#       print "($d) ";
#   list ($attr,$value) = split ("[=]",$d);
   ereg("([A-Za-z0-9-]{0,40}) *= *[, \"]([-A-Za-z0-9]{0,40})",$d,$t);
#   list ($attr,$value) = explode ("=,",$d);
#   ereg("([a-zA-z])[=]([a-z0-9A-z])",$d,$t);
#   ereg("([a-z0-9A-z]{1,9})[\ =]([a-z])",$d,$t);
   list ($w,$attr,$value) = $t;
#   print "(w $w a $attr v $value t $t)";
#   print "(a $attr v $value)";
  if (eregi("[Gg][Rr][Oo][Uu][Pp]",$attr))
#     print "$attr = $value ";
    array_push($argrp,$value);

   }
#       print "($d) ";
   }
   print "<br>";
}
fclose ($fp);

return $argrp;
}


function prts($st){
#$st=(string)$st;

#$st=strrev($st);
for($i=strlen($st),$j=0;$i>=0;$i--,$j++){

#for ($i=0;$i<strlen($st);$i++){
        
# if(($i+1)%3){
 if(($j)%3 || $j == 0 || $j == (strlen($st))){
        #$stt=$stt."$st[$i]";
        $stt="$st[$i]".$stt;
  }else{
        #if($i==(strlen($st)-1)) $stt=$stt."$st[$i]";
       #                 else    $stt=$stt."$st[$i]'";
#        if($j==0 ) $stt="<$st[$i]+".$stt;
#                        else    
#    if ($j !=( strlen($st) -1))
$stt="'$st[$i]".$stt;
        }

}

return (string)$stt;
#return (string)$st."--".$stt;
#return strrev($stt);
}

$style ="
<style type=\"text/css\">
.stxt{
        font-family: Helvetica, Helv, Sans-Serif;
        font-size: 10pt ; }
.txt{
        font-family: Arial, Helvetica, Helv, Sans-Serif;
        font-size: 12pt; }
.wtxt{
        font-family: Arial, Helvetica, Helv, Sans-Serif;
        font-size: 12pt; font-weight: bold; }
.bwtxt{
        font-family: Arial, Helvetica, Helv, Sans-Serif;
        font-size: 14pt; font-weight: bold; }
.textbox {
        font-family: Arial,Helvetica, sans-serif;
        font-size: 10pt;
        border-style: solid;
        border-top-width: 1px;
        border-right-width: 1px;
        border-bottom-width: 1px;
        border-left-width: 1px;
        border-color: #6B6B6B }

A:link {
 COLOR: black; FONT-FAMILY: Arial, Helvetica;
 TEXT-DECORATION: none }
A:visited {
 COLOR: black; FONT-FAMILY: Arial, Helvetica;
 TEXT-DECORATION: none }
A:hover {
 COLOR: black;
        FONT-FAMILY: Arial, Helvetica;
 TEXT-DECORATION: none }
</style>";


function print_error($er){
# echo  "<center><br><br>";
 echo  "<table width=60% border=0 cellpaddind=3 cellspacing=2>
        <tr><th align=center><font color=RED>Ошибка !
        <tr><td><hr width=100% size=1 noshade>";
 $er .="<tr><td><hr width=100% size=1 noshade>
        <tr><td align=center>
        <form><input type=button value=\"<< Назад\" OnClick=\"history.back()\"></form><p>";
 echo  "$er";
 echo  "</table>";
 echo  "</center></center></body></html>";
 exit;
}


$header ="
<html><head>
<meta http-equiv=\"Content-Type\" content=\"text/html; charset=koi8-r\">
<meta http-equiv=\"pragma\" content=\"no-cache\">
<meta http-equiv=\"cache-control\" content=\"no-cache\">
<title>Web User Interface</title>
$style
</head>";

$admin_header ="
<html><head>
<meta http-equiv=\"Content-Type\" content=\"text/html; charset=koi8-r\">
<meta http-equiv=\"pragma\" content=\"no-cache\">
<meta http-equiv=\"cache-control\" content=\"no-cache\">
<title>Web User Interface</title>
$style
</head>
<body bgcolor=\"#edede0\" link=\"#000000\" vlink=\"#000000\" alink=\"#000000\" style=\"font-family: Helvetica; font-size: 12pt;\">";

$end_frame ="</tr></tbody></table>";

$end_menu ="</center>";

$end_head ="</center></body></html>";

?>
