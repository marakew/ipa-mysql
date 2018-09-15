<?
	require("../inc/config.php");
	echo $admin_header;

#	echo "SESS"; print_r($_SESSION);
#	echo "REQ"; print_r($_REQUEST);
#	echo $action;

	$ouser = "admin";

	if (isset($_REQUEST['action'])) $action = $_REQUEST['action'];
	if (isset($_REQUEST['name']))   $name = $_REQUEST['name'];
	if (isset($_REQUEST['use']))    $use = $_REQUEST['use'];
	if (isset($_REQUEST['fmonth'])) $fmonth = $_REQUEST['fmonth'];
	if (isset($_REQUEST['money']))  $money = $_REQUEST['money'];
	if (isset($_REQUEST['rem']))    $rem = $_REQUEST['rem'];

?>

<?	if (isset($action) && $action == "user" && isset($name)){
#start_user_credit
	if (isset($use) && $use == "credit"){
		if (isset($money) && is_numeric($money)){
			if ($money == "0")
			$query = "UPDATE users SET credit = '0' WHERE name='$name'";
			else
			$query = "UPDATE users SET credit = '$money' WHERE name='$name'";
		#echo $query;
		$res = mysql_query("$query") or die("Error query $query");
		history_log("$name","Кредит <b>$money</b>");
		}
	}
#end_user_credit

#start_user_deposit
	if (isset($use) && $use == "deposit"){
		if (isset($money) && is_numeric($money)){
			if ($money == "0")
			$query = "UPDATE users SET deposit = '0' WHERE name='$name'";
			else
			$query = "UPDATE users SET deposit = deposit + '$money' WHERE name='$name'";
		#echo $query;
		$res = mysql_query("$query") or die("Error query $query");
		history_log("$name","Депозит <b>$money</b>");
		}
	}
#end_user_deposit

#start_user_trafcost
	if (isset($use) && $use == "trafcost"){
		if (isset($money) && is_numeric($money)){
			if ($money == "0")
			$query = "UPDATE users SET trafcost = '0' WHERE name='$name'";
			else
			$query = "UPDATE users SET trafcost = '$money' WHERE name='$name'";
		#echo $query;
		$res = mysql_query("$query") or die("Error query $query");
		history_log("$name","Стоимость траффика <b>$money</b>");
		}
	}
#end_user_trafcost

#start_user_traftype
	if (isset($use) && $use == "traftype"){
		if (isset($money) && is_numeric($money)){
			$query = "UPDATE users SET traftype = '$money' WHERE name='$name'";
		#echo $query;
		$res = mysql_query("$query") or die("Error query $query");
		history_log("$name","Тип траффика <b>$traftype[$money]</b>");
		}
	}
#end_user_traftype

#start_user_pay
	if (isset($use) && $use == "paycost"){
		if (isset($money) && is_numeric($money) && $money != 0){
		$query = "UPDATE users SET pay_cost='$money',pay_rem='$rem' WHERE name='$name'";
		$res = mysql_query("$query") or die("Error query $query");
		history_log("$name","Ежемесячный платеж <b>$money</b>");
		}
	}
	if (isset($use) && $use == "dpaycost"){
		$query = "UPDATE users SET pay_cost='0',pay_rem='' WHERE name='$name'";
		$res = mysql_query("$query") or die("Error query $query");
		history_log("$name","Ежемесячный платеж удален");
	}
#end_user_pay

	if (isset($use) && $use == "fcredit"){
?>
<center><br><b><font color=DARKGREEN>Счет (Кредит)</font><br>
<center><br><b>Пользователь: <font color=DARKED><?echo $name;?></font></b><br><br>
<form action="<?echo "$PHP_SELF?action=user&name=$name&use=credit";?>" method=post>
Добавить / Снять:
<input name=money class=textbox size=5 maxlenght=10>
<input type=hidden name=mmoney value=0>
<br><br><font class=stxt>При вводе <b>0</b> кредит обнулится</font>
<br><br><input type=submit name=report value=Изменить><br></form>
<?
	exit(0);
	}
	if (isset($use) && $use == "fdeposit"){
?>
<center><br><b><font color=DARKGREEN>Счет (Депозит)</font><br>
<center><br><b>Пользователь: <font color=DARKED><?echo $name;?></font></b><br><br>
<form action="<?echo "$PHP_SELF?action=user&name=$name&use=deposit";?>" method=post>
Добавить / Снять:
<input name=money class=textbox size=5 maxlenght=10>
<input type=hidden name=mmoney value=0>
<br><br><font class=stxt>При вводе <b>0</b> депозит обнулится</font>
<br><br><input type=submit name=report value=Изменить><br></form>
<?
	exit(0);
	}
	if (isset($use) && $use == "ftrafcost"){
?>
<center><br><b><font color=DARKGREEN>Стоимость траффика</font><br>
<center><br><b>Пользователь: <font color=DARKED><?echo $name;?></font></b><br><br>
<form action="<?echo "$PHP_SELF?action=user&name=$name&use=trafcost";?>" method=post>
Цена:
<input name=money class=textbox size=5 maxlenght=10>
<input type=hidden name=mmoney value=0>
<br><br><font class=stxt>При вводе <b>0</b> стоимость обнулится</font>
<br><br><input type=submit name=report value=Изменить><br></form>
<?
	exit(0);
	}
	if (isset($use) && $use == "ftraftype"){
?>
<center><br><b><font color=DARKGREEN>Тип траффика</font><br>
<center><br><b>Пользователь: <font color=DARKED><?echo $name;?></font></b><br><br>
<form action="<?echo "$PHP_SELF?action=user&name=$name&use=traftype";?>" method=post>
<table>
<tr bgcolor="#e5e1ed">
	<td width="%35">Тип:</td>
	<td><select name="money" class="textbox">
	<option value="0">Unlimit</option>
	<option value="1">Входящий</option>
	<option value="2">Исходящий</option>
	<option value="3">Вход+Исход</option>
	</td>
</tr>
</table>
<!--
<input name=money class=textbox size=5 maxlenght=10>
<input type=hidden name=mmoney value=0>
-->
<!--
<br><br><font class=stxt>При вводе <b>0</b> стоимость обнулится</font>
-->
<br><br><input type=submit name=report value=Изменить><br></form>


<?
	exit(0);
	}

	if (isset($use) && $use == "fpaycost"){
?>
<center><br><b><font color=DARKGREEN>Ежемесячный платеж</font><br>
<center><br><b>Пользователь: <font color=DARKED><?echo $name;?></font></b><br><br>
<form action="<?echo "$PHP_SELF?action=user&name=$name&use=paycost";?>" method=post>
Цена:<br>
<input name="money" class=textbox size=5 maxlenght=10><br>
Прим.:<br>
<textarea wrap="virtual" rows="4" cols="40" name="rem" class="textbox"></textarea>
<br><br><input type=submit name=report value=Добавить><br></form>
<?
	exit(0);
	}


} ?>

<?# if (isset($use) && $use == "stat" ) { ?>
<center>
<a href="index.php"><img src="pic/main.gif" border="0"></a>
<a href="index.php?action=history"><img src="pic/history.gif" border="0"></a>
<?
	if ($action != "history"){
	$lnk = "?action=user";
	if (isset($name))
		$lnk .= "&name=$name";
	if (isset($use))
		$lnk .= "&use=info";
	if (isset($fmonth))
		$lnk .= "&fmonth=$fmonth";
?>
<center>
<form method="post" action="<?echo $PHP_SELF.$lnk?>">
<table>
<tr><td><select name="fmonth">
<?
 $query = "SELECT date_format(from_unixtime(tm1),'%Y-%m') FROM rules GROUP BY date_format(from_unixtime(tm1),'%Y %m')";
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
<td><input type="submit" value=" Показать "></td>
</table>
</form>
<?
	$lnk = "&name=$name";
?>

<? if (isset($name)) { ?>
<center>
<table width="80%" border="0" cellpadding="3" cellspacing="2" align="center">
<tbody>
<tr class="stxt" bgcolor="#c8c8ff">
<th width="10%">name</th>
<th width="10%">ip</th>
<th width="12%"><a href="?action=user&use=fdeposit<?echo $lnk?>"><font color=#F01F00>deposit</font></a></th>
<th width="10%"><a href="?action=user&use=fcredit<?echo $lnk?>"><font color=#F01F00>credit</font></a></th>
<th width="10%"><a href="?action=user&use=ftrafcost<?echo $lnk?>"><font color=#F01F00>trafcost</font></a></th>
<th width="10%"><a href="?action=user&use=ftraftype<?echo $lnk?>"><font color=#F01F00>traftype</font></a></th>
<th width="5%">status</th>
<th width="20%">rname</th>
</tr>
<?
	$query = "SELECT name,ip,rname,round(deposit,2),trafcost,rule,traftype,credit,pay_cost,pay_rem FROM users WHERE name='$name'";
	#echo $query;
	$resu = mysql_query("$query") or die("Error query <font color=\"RED\">$query</font>");
	$rowu = mysql_fetch_array($resu);
	$traf = $rowu[6];
	$deposit = $rowu[3];
	$credit = $rowu[7];

	if ( (($deposit + $credit) > 0.01) || ($traf == 0))
		$block = 0;
	else
		$block = 1;

echo "<tr align=\"center\" class=\"stxt\">";
echo	"<td><b>$rowu[0]</b></td>
	 <td>$rowu[1]</td>
	 <td>$deposit</td>
	 <td>$rowu[7]</td>
	 <td>$rowu[4]</td>
	 <td>$traftype[$traf]</td>
	 <td>$status[$block]</td>
	 <td>$rowu[2]</td>
	 </tr>";

?>
</tbody></table>
<br><br>
</center>
<? } ?>

<? if(isset($name)){ ?>
<center>
<table width="50%" border="1" cellpadding="3" cellspacing="2" align="center">
<tbody>
<tr class="stxt">
<th colspan="2" align="center" bgcolor="#c8c8ff">Ежемесячные платежи</th>
</tr>
<? if (isset($rowu[8]) && is_numeric($rowu[8]) && $rowu[8] != 0) { ?>
<tr class="stxt">
<th width="10%" bgcolor="#c8c8ff">Сумма</th>
<td><?echo $rowu[8];?></td>
</tr>
<tr class="stxt">
<th width="10%" bgcolor="#c8c8ff">Прим.</th>
<td><?echo $rowu[9];?></td>
</tr>
<tr class="stxt">
<th colspan="2"><a href="<?echo $PHP_SELF;?>?action=user&use=dpaycost<?echo $lnk;?>"><font color="#ff0000">delete</font></a></th>
</tr>
<? } else { ?>
<tr class="stxt">
<th colspan="2"><a href="<?echo $PHP_SELF;?>?action=user&use=fpaycost<?echo $lnk;?>"><font color="#ff0000">add</font></a></th>
</tr>
<? } ?>
</tbody></table>
<br><br>
</center>

<? } ?>

<? if(isset($name)){ 
$date_c = date("Y-m-d");
echo "<td width=60%>
	<div><b> Graph $date_c</b></div>
	<a href=\"../img/$name.html\"><img border=1 src=\"../img/$name-day.png\"</a><br>
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
<th width="10%">date</th>
<th width="8%">InBytes</th>
<th width="8%">OutBytes</th>
<th width="8%">cost</th>
<? if (!isset($name)) { ?>
<th width="8%">deposit</th>
<th width="20%">rname</th>
<? } ?>

</tr>

<?

 if (!isset($name)) { 
	$query = "SELECT name,ip,rname,round(deposit,2),trafcost,rule FROM users ORDER BY ip";
  } else {
		# who
	$query = "SELECT round(SUM(round(cost,2)),2),SUM(byte_in),SUM(byte_out),date_format(from_unixtime(tm1),'%Y-%m-%d') from rules where who='$rowu[5]'";

 if (isset($fmonth)){
	$query .= " AND date_format(from_unixtime(tm1),'%Y-%m') = '$fmonth'";
  }else{
	# %d hmm
	$query .= " AND date_format(from_unixtime(tm1),'%Y-%m') = date_format(NOW(),'%Y-%m')";
	$fmonth = date("Y-m");
  }

	$query .= " group by date_format(from_unixtime(tm1),'%Y-%m-%d'),who";

  }
	#echo $query;
	$res = mysql_query("$query") or die("Error query <font color=\"RED\">$query</font>");

	if (isset($fmonth)){
	}else{
	}

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

 if (!isset($name)) { 
		# who
	$query = "SELECT round(SUM(round(cost,2)),2),SUM(byte_in),SUM(byte_out),date_format(from_unixtime(tm1),'%Y-%m') from rules where who='$row[5]'";

 if (isset($fmonth)){
	$query .= " AND date_format(from_unixtime(tm1),'%Y-%m') = '$fmonth'";
  }else{
	$query .= " AND date_format(from_unixtime(tm1),'%Y-%m') = date_format(NOW(),'%Y-%m')";
	$fmonth = date("Y-m");
  }
	$query .= " group by date_format(from_unixtime(tm1),'%Y-%m'),who";
	#echo $query;
	$resr = mysql_query("$query") or die("Error query <font color=\"RED\">$query</font>");
	$rowr = mysql_fetch_array($resr);

	if ($row[3] <= 0.01){
		$deposit = "<font color=#ff0000>$row[3]</font>";
	} else {
		$deposit = "<font color=#0000ff>$row[3]</font>";
	}

echo	"<td><a href=\"$PHP_SELF?action=user&name=$row[0]&use=info&fmonth=$fmonth\"><b>$row[0]</b></a></td>
	 <td>$row[1]</td>
	 <td>$rowr[3]</td>
	 <td>".prts($rowr[1])."</td>
	 <td>".prts($rowr[2])."</td>
	 <td>$rowr[0]</td>
	 <td>$deposit</td>
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

	# end of table SUMMARIZE !

 if (isset($name)){
			# who
	$query = "SELECT round(SUM(round(cost,2)),2),SUM(byte_in),SUM(byte_out),date_format(from_unixtime(tm1),'%Y-%m') from rules where who='$rowu[5]'";

 if (isset($fmonth)){
	$query .= " AND date_format(from_unixtime(tm1),'%Y-%m') = '$fmonth'";
  }else{
	$query .= " AND date_format(from_unixtime(tm1),'%Y-%m') = date_format(NOW(),'%Y-%m')";
	$fmonth = date("Y-m");
  }
	$query .= " group by date_format(from_unixtime(tm1),'%Y-%m'),who";
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
<? #} ?>

<?

}

	if (isset($action) && $action == "history"){
?>
<center>
<form method="post" action="<?echo "$PHP_SELF?action=history";?>">
<table>
<tr><td><select name="fmonth">
<?
 $query = "SELECT date_format(date,'%Y-%m') FROM history GROUP BY date_format(date,'%Y %m')";

        $res = mysql_query("$query") or
                        die("Error query <font color=\"RED\">$query</font>");
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

<?
 if (!isset($fmonth)) $fmonth = date("Y-m");

 $query = "SELECT name,date_format(date,'%d %H:%i:%s'),action,operator FROM history";
 $query .= " WHERE date_format(date,'%Y-%m') = '$fmonth'";
 $query .= " ORDER BY date";
# echo $query;
 $res = mysql_query("$query") or
                die("Error query <font color=\"RED\">$query</font>");
?>
<br><center><b>History</b><br><br>
<table width="80%" border="0" cellpadding="2" cellspacing="2">
<tbody>
<tr class="stxt" bgcolor="#c8c8ff">
    <th width="13%">Имя</th>
    <th width="20%">Дата</th>
    <th width="55%">Действие</th>
    <th width="15%">Оператор</th>
</tr>
<?  $flagcolor = 0;
while(($row = mysql_fetch_array($res))){
   echo "<tr align=\"center\" class=\"stxt\"";
  if($flagcolor == 1){
   echo " bgcolor=\"#e1e1e1\">"; $flagcolor = 0;
   }else{
   echo ">";                     $flagcolor = 1;
 }
echo "<td><a href=\"$PHP_SELF?action=user&name=$row[0]&use=info\"><b>$row[0]</b></a></td>";
 echo "<td>$row[1]</td>";
 echo "<td>$row[2]</td>";
 echo "<td>$row[3]</td>";
?>
</tr>
<?}?>
</tbody>
</table>
</center>

<?
	}

 echo $end_head; exit; 
?>
