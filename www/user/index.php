<?
	unset($_SESSION['ouser']);

	session_name("userleasedline");
	session_start();

	if (isset($_SESSION['ouser'])){
		$name = $_SESSION['ouser'];
	}

	if(isset($_REQUEST['action']) && ($_REQUEST['action'] == "exit" ) ||
	   (isset($_SESSION['timeout']) && intval((time()-$_SESSION['timeout'])/60) > 1)){
		session_start();
		session_unset();
		session_destroy();
		session_regenerate_id();
	}

	$_SESSION['timeout'] = intval(time());

	require("../inc/config.php");
	echo $admin_header;

        if (isset($_REQUEST['action'])) $action = $_REQUEST['action'];
        if (isset($_REQUEST['name']))   $name = $_REQUEST['name'];
        if (isset($_REQUEST['use']))    $use = $_REQUEST['use'];
        if (isset($_REQUEST['fmonth'])) $fmonth = $_REQUEST['fmonth'];

#        if (isset($_SESSION['rule'])) $rule = $_SESSION['rule'];

#	echo $_SERVER['PHP_SELF'];
#	print_r($_SESSION);
#	print_r($_REQUEST);
#	print_r($_SERVER);

	if (!isset($_SESSION['ouser'])){

		if (isset($_REQUEST['action']) && $_REQUEST['action'] == "login"){

#		$username = $_REQUEST['username'];
#		$password = $_REQUEST['password'];

		$query = "SELECT name,passwd,rule FROM users WHERE name='".mysql_escape_string($_REQUEST['username'])."'";
#		echo $query;

		$resouser = mysql_query("$query") or die("Error query $query");
		$puser = mysql_fetch_array($resouser);
		if (@mysql_num_rows($resouser) == 1 &&
			crypt($_REQUEST['password'], substr($puser[passwd],0,2)) == $puser[passwd]){
		$_SESSION['ouser'] = $puser[name];
		session_register("ouser");
		$_SESSION['rule'] = $puser[rule];
		session_register("rule");

		$_SESSION['timeout'] = intval(time());
		session_register("timeout");

		unset($action);
		$name = $_SESSION['ouser'];
		}
		}
		if (!isset($_SESSION['ouser'])){
?>
<body bgcolor="#edede0">
<center><h3>Интерфейс Пользователей</h3>
<h3><hr size="1" noshade="" align="center" width="50%">
<center>
<form action="<?echo $_SERVER['PHP_SELF']?>?action=login" method="post">
<table width="35%" border="0" cellpadding="3" cellspacing="2">
<tbody>
<tr><td width="65%" class="wtxt">Пользователь:</td>
    <td width="45%"><input name="username" class="textbox" size="12" maxlength="15">
</td></tr>
<tr><td width="65%" class="wtxt">Пароль:</td>
    <td width="45%"><input type="password" name="password" class="textbox" size="12" maxlength="15">
</td></tr>
</tbody>
</table>
<hr size="1" noshade="" align="center" width="50%">
<input type="submit" name="report" value="  Вход  ">
</form>
<?
	echo $end_menu; echo $end_head; exit; }
	}
?>

<? ################################## main status ?>
<center>  
<table width="730" align="center" border="0" cellspacing="0" cellpadding="5">
        <tbody>
        <tr class="stxt">
        <td><b><?echo date("d"); echo " ".$monthy[date("m")]."  "; echo date("Y H:i:s");?></b></td>
        <td align="right"><b>Пользователь: <?echo $_SESSION['ouser']?> [<a href="<?echo $PHP_SELF?>?action=exit"> Выход </a>]</b></td>
        </tr>
        </tbody>
</table>

<?# if (isset($use) && $use == "stat" ) { ?>


<center>
<form method="post" action="<?echo $_SERVER['PHP_SELF']?>?use=stat">
<table>
<tr><td><select name="fmonth">
<?
# $rule = $_SESSION['rule'];

 $query = "SELECT date_format(from_unixtime(tm1),'%Y-%m') FROM rules WHERE who='".$_SESSION['rule']."' GROUP BY date_format(from_unixtime(tm1),'%Y %m')";
 $res = mysql_query("$query") or die("Error query <font color=\"RED\">$query</font>");
 $fselected = 0;
while(($row = mysql_fetch_array($res))){
 if (($fmonth == $row[0] || (date("Y-m") == $row[0] && !isset($fmonth))) && fselected == 0 ){
 echo "<option selected value=\"$row[0]\">$row[0]";
 $fselected = 1;
 }else{
 echo "<option value=\"$row[0]\">$row[0]";
 }
}
?>
</select></td>
<td><input type="submit" value="Показать"></td>
</table>
</form>


<? if (isset($name)) { ?>
<center>
<table width="60%" border="0" cellpadding="3" cellspacing="2" align="center">
<tbody>
<tr class="stxt" bgcolor="#c8c8ff">
<th width="10%">name</th>
<th width="10%">ip</th>
<th width="12%">deposit</th>
<th width="10%">credit</th>
<th width="10%">trafcost</th>
<th width="10%">traftype</th>
<th width="5%">status</th>
<th width="20%">rname</th>
</tr>
<?
#	$query = "SELECT cost FROM rules WHERE who='$name' ORDER BY tm2 DESC";
#	#echo $query;
#	$resu = mysql_query("$query") or die("Error query <font color=\"RED\">$query</font>");
#	$rowu = mysql_fetch_array($resu);
#	$cost = $rowu[0];

	$query = "SELECT name,ip,rname,round(deposit,2),trafcost,rule,traftype,credit,pay_cost,pay_rem FROM users WHERE name='$name'";
	#echo $query;
	$resu = mysql_query("$query") or die("Error query <font color=\"RED\">$query</font>");
	$rowu = mysql_fetch_array($resu);
	$traft = $rowu[6];
#	$deposit = (($rowu[3] + $rowu[7]) - $cost);
	$deposit = $rowu[3];
	$credit = $rowu[7];

	if ((($deposit + $credit) > 0.01) || ($traft == 0))
		$block = 0;
	else
		$block = 1;

echo "<tr align=\"center\" class=\"stxt\">";
echo	"<td><b>$rowu[0]</b></td>
	 <td>$rowu[1]</td>
	 <td>$deposit</td>
	 <td>$rowu[7]</td>
	 <td>$rowu[4]</td>
	 <td>$traftype[$traft]</td>
	 <td>$status[$block]</td>
	 <td>$rowu[2]</td>
	 </tr>";

?>
</tbody></table>
<br><br>
</center>
<? } ?>
<? if(isset($name) && (isset($rowu[8]) && is_numeric($rowu[8]) && $rowu[8] != 0))
{?>
<center>
<table width="50%" border="1" cellpadding="3" cellspacing="2" align="center">
<tbody>
<tr class="stxt">
<th colspan="2" align="center">Ежемесячный платьеж</th>
</tr>
<tr class="stxt">
<th width="10%" bgcolor="#c8c8ff">Цена</th>
<td><?echo $rowu[8];?></td>
</tr>
<tr class="stxt">
<th width="10%" bgcolor="#c8c8ff">Прим.</th>
<td><?echo $rowu[9];?></td>
</tr>

</tbody></table>
<br><br>
</center>

<? } ?>
<? if(isset($name)){ 
$date_c = date("Y-m-d");
echo "<td width=60%>
	<div><b> Graph $date_c</b></div>
	<img border=1 src=\"../img/$name-day.png\"<br>
	<tr>
	<td colspan=2>
	<center><br>";
} ?>

<center>
<table width="90%" border="0" cellpadding="3" cellspacing="2" align="center">
<tbody>

<tr class="stxt" bgcolor="#c8c8ff">

<? if (!isset($name)) { ?>
<th width="10%">name</th>
<th width="10%">ip</th>
<? } ?>
<th width="5%">date</th>
<th width="8%">InBytes</th>
<th width="8%">OutBytes</th>
<th width="8%">cost</th>
<? if (!isset($name)) { ?>
<th width="20%">rname</th>
<? } ?>

</tr>

<?

 if (!isset($name)) { 
	$query = "SELECT name,ip,rname,round(deposit,2),trafcost,rule,traftype FROM users ORDER BY ip";
  } else {		#who
	$query = "SELECT round(SUM(round(cost,2)),2),SUM(byte_in),SUM(byte_out),date_format(from_unixtime(tm1),'%Y-%m-%d') FROM rules WHERE who='$rowu[5]'";

 if (isset($fmonth)){
	$query .= " AND date_format(from_unixtime(tm1),'%Y-%m') = '$fmonth'";
  }else{
	# %d hmm
	$query .= " AND date_format(from_unixtime(tm1),'%Y-%m') = date_format(NOW(),'%Y-%m')";
	$fmonth = date("Y-m");
  }

	$query .= " GROUP BY date_format(from_unixtime(tm1),'%Y-%m-%d'),who";
	# set DAY
  }
	#echo $query;
	$res = mysql_query("$query") or die("Error query <font color=\"RED\">$query</font>");

#	if (isset($fmonth)){
#	}else{
#	}

	$flagcolor = 0;
while(($row = mysql_fetch_array($res))){
	echo "<tr align=\"center\" class=\"stxt\"";
    if($flagcolor == 1){
	echo " bgcolor=\"#e1e1e1\"";
	$flagcolor = 0;
    } else { 
	$flagcolor =  1;
    }
	echo ">";
	# create table !
 if (!isset($name)) { 
	# if no set name - sum BY MONYH 
			# who
	$query = "SELECT round(SUM(round(cost,2)),2),SUM(byte_in),SUM(byte_out),date_format(from_unixtime(tm1),'%Y-%m') from rules where who='$row[5]'";

 if (isset($fmonth)){
	$query .= " AND date_format(from_unixtime(tm1),'%Y-%m') = '$fmonth'";
  }else{
	$query .= " AND date_format(from_unixtime(tm1),'%Y-%m') = date_format(NOW(),'%Y-%m')";
	$fmonth = date("Y-m");
  }
	$query .= " GROUP BY date_format(from_unixtime(tm1),'%Y-%m'),who";
	#echo $query;
	$resr = mysql_query("$query") or die("Error query <font color=\"RED\">$query</font>");
	$rowr = mysql_fetch_array($resr);

echo	"<td><a href=\"$PHP_SELF?action=user&name=$row[0]&use=info&fmonth=$fmonth\"><b>$row[0]</b></a></td>
	 <td>$row[1]</td>
	 <td>$rowr[3]</td>
	 <td>".prts($rowr[1])."</td>
	 <td>".prts($rowr[2])."</td>
	 <td>$rowr[0]</td>
	 <td>$row[2]</td>
	 </tr>";
 } else {

echo	"<td>$row[3]</td>
	 <td>".prts($row[1])."</td>
	 <td>".prts($row[2])."</td>
	 <td>$row[0]</td>
	 </tr>";

 }


}
	# end of table - SUMMARY

 if (isset($name)){
			# who
	$query = "SELECT round(SUM(round(cost,2)),2),SUM(byte_in),SUM(byte_out),date_format(from_unixtime(tm1),'%Y-%m') FROM rules WHERE who='$rowu[5]'";

 if (isset($fmonth)){
	$query .= " AND date_format(from_unixtime(tm1),'%Y-%m') = '$fmonth'";
  }else{
	$query .= " AND date_format(from_unixtime(tm1),'%Y-%m') = date_format(NOW(),'%Y-%m')";
	$fmonth = date("Y-m");
  }
	$query .= " GROUP BY date_format(from_unixtime(tm1),'%Y-%m'),who";
	#echo $query;
	$ress = mysql_query("$query") or die("Error query <font color=\"RED\">$query</font>");
	$rows = mysql_fetch_array($ress);

echo	"<tr align=\"center\" class=\"stxt\" bgcolor=\"#21ae91\">
	 <td>&nbsp;</td>
	 <td>".prts($rows[1])."</td>
	 <td>".prts($rows[2])."</td>
	 <td>$rows[0]</td>
	 </tr>";

 }

?>

</tbody></table>
<br><br>
</center>
<?# } ?>

<? echo $end_head; exit; ?>
