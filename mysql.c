#include <syslog.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "rules.h"
#include "common.h"
#include "config.h"
#include "db.h"
#include "debug.h"

#include <my_global.h>
#include <my_sys.h>
#include <m_string.h>
#include "mysql.h"
#include <time.h>

char		*sql_name;
char		*sql_user;
char		*sql_pswd;
char		*sql_host;
int		sql_port;
MYSQL		*mysql = NULL;

/* query */
#define MAX_Q 1024
char q[MAX_Q], *end_q;

/*
 * reconnect to database
 */
MYSQL *
reconnect_sql_db(void){

	int	i = 0;
	MYSQL *mysql = NULL;

		syslog(LOG_INFO, "MYSQL:%s %d", __FUNCTION__, MYSQL_VERSION_ID);
#if MYSQL_VERSION_ID >= 40013
        mysql_init(&real_mysql);
	for (i = 0; i < 6; i++)
	if (!mysql_real_connect(&real_mysql,
				sql_host,
				sql_user,
				sql_pswd,
				sql_name, 0, NULL, CLIENT_FOUND_ROWS)) {
		syslog(LOG_ERR, "MYSQL: Cannot Connect to %s@%s:%s",
			sql_host,sql_user,sql_name);
		mysql = NULL;
		sleep(5);
        } else {
		mysql = &real_mysql;
		break;
	}
#else
	for (i = 0; i < 6; i++)
        if (!mysql_connect(&real_mysql,sql_host,sql_user,sql_pswd)){
		syslog(LOG_ERR, "MYSQL: Cannot Connect to %s@%s:%s",
			sql_host,sql_user,sql_name);
		mysql = NULL;
		sleep(5);
        } else {
		mysql = &real_mysql;
		break;
	}
	if (mysql != NULL)
	      for (i = 0; i < 6; i++)
		if (mysql_select_db(mysql,sql_name)){
			syslog(LOG_ERR, "MYSQL cannot select db %s",sql_name);
			syslog(LOG_ERR, "MYSQL error: %s",mysql_error(mysql));
			sleep(5);
        	} else {
			return mysql;
		}
#endif
	syslog(LOG_ERR, "MYSQL: Giving up on connect");
	return mysql;

}

/* query to mysql */
static int
do_sql_query(const char* q, uint l){
	int r = 0;
	int i = 0;

	while (i < 10){

	if (mysql == NULL && !(mysql = reconnect_sql_db()))
		return -1;
//		if (mysql == NULL)
//			mysql = reconnect_sql_db();
#if 1
    	r = mysql_real_query(mysql, q, l);
#else
	r = mysql_query(mysql, q);
#endif
	if (r == 0){
		return 1;
	}

	if (!strcasecmp(mysql_error(mysql),"MySQL server has gone away")){
		syslog(LOG_ERR,"MYSQL Error (retrying %d): Cannot Query:%s",i,q);
		syslog(LOG_ERR,"MYSQL error: %s", mysql_error(mysql));
		mysql_close(mysql);
		mysql = NULL;
	} else {
		syslog(LOG_ERR,"MYSQL Error (%d): Cannot Query:%s", r, q);
		syslog(LOG_ERR,"MYSQL error: %s", mysql_error(mysql));
		return -1;
	}
		i++;
	}

    return -1;
}

static int
init_sql_db_rules(void){

		end_q = (char *)strxmov(q,
		"CREATE TABLE IF NOT EXISTS rules"
		" (who varchar(32) NOT NULL default '',"
		" cost double NOT NULL default '0',"
		" tm1 datetime NOT NULL default '2000-01-01 00:00:00',"
		" tm2 datetime NOT NULL default '0000-00-00 00:00:00',"
		" byte bigint unsigned NOT NULL default '0',"
		" byte_in bigint unsigned NOT NULL default '0',"
		" byte_out bigint unsigned NOT NULL default '0', PRIMARY KEY (who,tm1) ) TYPE=MyISAM", NullS);

		if (do_sql_query(q, (uint)(end_q - q)) < 0){
			return -1;
		}

	return 0;
}

/*
 * Connect to database sql_name
 */
int
init_sql_db(void){

	if (mysql == NULL && !(mysql = reconnect_sql_db()))
		return -1;
	if (init_sql_db_rules() < 0)
		return -1;

	time(&curr_time);
	localtime_r(&curr_time, &curr_tm);
/*	curr_time = timegm(&curr_tm);*/

	return 0;
}

/*
 * Append a new record for *rule accounting rule in database.
 * Update rule->newrec_time field.
 */
int
append_sql_db(struct rule *rule, const u_quad_t *value_ptr){
	u_quad_t byte_in, byte_out;

	MYSQL_RES *res;
	MYSQL_ROW row;
	char            datebuf[100];
	time_t		curr_time_;
	struct tm	curr_tm_;

	if (rule->whoname == NULL)
		return 0;

//	time(&curr_time_);
	localtime_r(&curr_time, &curr_tm_);
	strftime(datebuf, sizeof(datebuf), "%Y%m%d%H%M%S", &curr_tm_);


	switch(rule->row){
	case 1: /* row IN */
		byte_in = *value_ptr;
		byte_out = 0;
		break;
	case 2: /* row OUT */
		byte_in = 0;
		byte_out = *value_ptr;
		break;
	default:
		byte_in = 0;
		byte_out = 0;
		break;
	}

	if (rule->state == 1){ // if state BLOCK
		byte_in = 0;
		byte_out = 0;
	}

	snprintf(q, MAX_Q, 
	"INSERT INTO rules (who, tm1, tm2, byte_in, byte_out, cost) VALUES ('%s', '%s', '%s', %qu, %qu, 0)",
		rule->whoname,
		datebuf,
		datebuf,
		byte_in,
		byte_out);

	/* newrec_time will be checked if "append_db_time" parameter was
	   specified in the configuration file for *rule rule */
	rule->newrec_time = curr_time + rule->append_db_time;

	if (do_sql_query(q, (uint) strlen(q)) < 0){
		return -1;
	}

	return 0;
}

/*
 * Update current record for *rule accounting rule in database.
 * value is equal to new value of counter.
 */
int
update_sql_db(const struct rule *rule, const u_quad_t *value_ptr){

	MYSQL_RES *res;
	MYSQL_ROW row;
	char            datebuf[100];
	char            sdatebuf[100];
	time_t		start_time;
	struct tm	start_tm;
	time_t		curr_time_;
	struct tm	curr_tm_;

	if (rule->whoname == NULL)
		return 0;

//	time(&curr_time_);
	localtime_r(&curr_time, &curr_tm_);
	strftime(datebuf, sizeof(datebuf), "%Y%m%d%H%M%S", &curr_tm_);

	start_time = (rule->newrec_time - rule->append_db_time);
	localtime_r(&start_time, &start_tm);
	strftime(sdatebuf, sizeof(datebuf), "%Y%m%d%H%M%S", &start_tm);


     if (rule->state == 1){ // if state BLOCK

	snprintf(q, MAX_Q, 
	"UPDATE rules set tm2='%s' WHERE tm1='%s' AND who='%s'",
		datebuf,
		sdatebuf,
		rule->whoname);

      } else {			// if state COUNT

	switch(rule->row){
	case 1: /* row IN */

	snprintf(q, MAX_Q, 
	"UPDATE rules set tm2='%s', byte_in=%qu WHERE tm1='%s' AND who='%s'",
		datebuf,
		*value_ptr,
		sdatebuf,
		rule->whoname);

		break;
	case 2: /* row OUT */

	snprintf(q, MAX_Q, 
	"UPDATE rules set tm2='%s', byte_out=%qu WHERE tm1='%s' AND who='%s'",
		datebuf,
		*value_ptr,
		sdatebuf,
		rule->whoname);

		break;

	default:

	snprintf(q, MAX_Q, 
	"UPDATE rules set tm2='%s', byte=%qu WHERE tm1='%s' AND who='%s'",
		datebuf,
		*value_ptr,
		sdatebuf,
		rule->whoname);

		break;
	}
      }

	if (do_sql_query(q, (uint) strlen(q)) < 0){
		return -1;
	}
	return 0;
}

/*
 *
 */
int
sql_billing(struct rule *rule, struct ip_fw *kipfw_){

	MYSQL_RES *res;
	MYSQL_ROW row;

	struct ipfwac   *fwacp = rule->ipfwac;
	double deposit = 0, credit = 0, trafcost = 0;
	double cost = 0, cost_c = 0, cost_s = 0;
	double traf_cost = 0;
	double ONEmb = 0;
	int traftype = 0;
	int status;
	long byte_in = 0, byte_out = 0;

	char            datebuf[100];
	char            sdatebuf[100];
	time_t		start_time;
	struct tm	start_tm;
	time_t		curr_time_;
	struct tm	curr_tm_;

	if (rule->whoname == NULL)
		return 0;


	time(&curr_time_);
	localtime_r(&curr_time_, &curr_tm_);
	strftime(datebuf, sizeof(datebuf), "%Y%m%d%H%M%S", &curr_tm_);

	start_time = (rule->newrec_time - rule->append_db_time);
	localtime_r(&start_time, &start_tm);
	strftime(sdatebuf, sizeof(datebuf), "%Y%m%d%H%M%S", &start_tm);

	snprintf(q, MAX_Q, 
	"SELECT deposit,credit,trafcost,traftype,1mb FROM users"
	" WHERE rule='%s'",
		rule->whoname);

	if (do_sql_query(q, (uint) strlen(q)) < 0){

		syslog(LOG_ERR, "%s: SQL Error: %s", __FUNCTION__, q);
	} else {
		if (!(res = mysql_store_result(mysql)) && mysql_field_count(mysql)){
			mysql_free_result(res);
		} else {
			while ((row = mysql_fetch_row(res))){
				deposit = atof(row[0]);
				credit = atof(row[1]);
				trafcost = atof(row[2]);
				traftype = atoi(row[3]);
				ONEmb = atof(row[4]);
			}

			mysql_free_result(res);
		}
	}

	if (traftype == 0){
		return 0;
	}

#if 1	/* for fast */
	switch(rule->row){
	case 1: /* row IN */
		if (traftype == 2){
			if ( ((deposit + credit) > 0.01))
				status = 0; /* unblock */
			else {	status = 1; /* block */
			}
			goto check_new_rec; 
		}	
		break;
	case 2: /* row OUT */
		if (traftype == 1){
			if ( ((deposit + credit) > 0.01))
				status = 0; /* unblock */
			else {	status = 1; /* block */
			}			
			goto check_new_rec;	
		}
		break;
	case 3: /* other */
		break;
	default:
		goto end_billing;
	}	
#endif

	if ( ((deposit + credit) > 0.01)){
		status = 0; /* unblock */

	sprintf(q, 
	"SELECT byte_in,byte_out,cost FROM rules WHERE who='%s' AND tm1='%s'",
		rule->whoname,
		sdatebuf);

	if (do_sql_query(q, (uint) strlen(q)) < 0){
		syslog(LOG_ERR, "%s: SQL Error: %s", __FUNCTION__, q);
	} else {
		if (!(res = mysql_store_result(mysql)) && mysql_field_count(mysql)){
			mysql_free_result(res);
		} else {
			while ((row = mysql_fetch_row(res))){
				byte_in = atol(row[0]);
				byte_out = atol(row[1]);
				cost_s = atof(row[2]);
			}
			mysql_free_result(res);

		}
	}

	switch(traftype){
	case 0: /*unlimit */
		status = 0;
		goto end_billing;
		break;
	case 1: /* IN */
		cost_c = (byte_in + 0.0) * (trafcost / (ONEmb));
		break;
	case 2: /* OUT */
		cost_c = (byte_out + 0.0) * (trafcost / (ONEmb));
		break;
	case 3: /* IN + OUT */
		cost_c = ((byte_out + byte_in + 0.0) * (trafcost / ONEmb));
		break;
	default:
		;
	}


	/* change if we in ROW!!! */
	switch(rule->row){
	case 1: /* row IN */
		if (traftype != 2){
			cost = (cost_c - cost_s);
			deposit = deposit - cost;
		} else {
			goto end_billing;
		}
		break;
	case 2: /* row OUT */
		if (traftype != 1){
			cost = (cost_c - cost_s);
			deposit = deposit - cost;
		} else {
			goto end_billing;
		}
		break;
	case 3: /* other */
		break;

	default:
			goto end_billing;
#if 1
			cost = cost_s;
			deposit = deposit;
#endif
	}	

	sprintf(q, 
		"UPDATE rules SET cost='%4.9f' WHERE who='%s' AND tm1='%s'",
			cost_c,
			rule->whoname,
			sdatebuf);

		if (do_sql_query(q, (uint) strlen(q)) < 0){
			syslog(LOG_ERR, "%s: SQL Error: %s", __FUNCTION__, q);
		}


	if ( ((deposit + credit) - cost) <= 0.009){
		status = 1; /* block */
	} else {
		status = 0; /* unblock */
	}

	sprintf(q, 
		"UPDATE users SET deposit='%4.9f' WHERE rule='%s'",
			deposit,
			rule->whoname);

		if (do_sql_query(q, (uint) strlen(q)) < 0){
			syslog(LOG_ERR, "%s: SQL Error: %s", __FUNCTION__, q);
		}

     } else {
		status = 1; /* block */
     } 

check_new_rec:

	if (status == 1 && rule->state == 0){
	/* appaned new rec after calculate Deposit */
		snprintf(q, MAX_Q, 
		"UPDATE rules SET tm2='%s' WHERE tm1='%s' AND who='%s'",
		datebuf,
		sdatebuf,
		rule->whoname);

		if (do_sql_query(q, (uint) strlen(q)) < 0){
			syslog(LOG_ERR, "%s: SQL Error: %s",__FUNCTION__, q);
		}

		snprintf(q, MAX_Q, 
		"INSERT INTO rules (who, tm1, tm2, byte_in, byte_out, cost)"
		" VALUES ('%s', '%s', '%s', 0, 0, 0)",
		rule->whoname,
		datebuf,
		datebuf);

		rule->bcnt = 0;
		rule->newrec_time = curr_time + rule->append_db_time; // hmmm FIXX

		if (do_sql_query(q, (uint) strlen(q)) < 0){
			syslog(LOG_ERR, "%s: SQL Error: %s",__FUNCTION__, q);
		} 
	}

end_billing:

	if (status){
		rule->state = 1;
#if __FreeBSD_version < 500000  /* 4.11 */
		kipfw_change_table(kipfw_, IP_FW_F_DENY);
#else	/* 5.x */
		kipfw_change_table(kipfw_, O_DENY);
#endif
	} else {
		rule->state = 0;
#if __FreeBSD_version < 500000  /* 4.11 */
		kipfw_change_table(kipfw_, IP_FW_F_COUNT);
#else	/* 5.x */
		kipfw_change_table(kipfw_, O_COUNT);
#endif
	}
}
