CREATE TABLE IF NOT EXISTS users (
	name varchar(32) NOT NULL default '',
	passwd varchar(13) NOT NULL default '*',
	deposit double NOT NULL default '0',
	credit smallint(5) NOT NULL default '0',
	rname varchar(100) NOT NULL default '',
	rule varchar(32) NOT NULL default '',
	ip varchar(15) NOT NULL default '0.0.0.0',
	mac varchar(20) NOT NULL default '00:00:00:00:00:00',
	trafcost double NOT NULL default '0',
	traftype smallint(1) NOT NULL default '0',
	1mb double NOT NULL default '1000000',
	pay_cost double NOT NULL default '0',
	pay_rem varchar(255) NOT NULL default '',
	PRIMARY KEY (name,rule)
) TYPE=MyISAM;
