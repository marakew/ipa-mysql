#ifdef WITH_MYSQL
#include <mysql.h>
#include <mysql_version.h>
extern char            *sql_name;
extern char            *sql_user;
extern char            *sql_pswd;
extern char            *sql_host;
extern int             sql_port;
#define        SQLUSER NULL
#define        SQLPSWD NULL
#define        SQLHOST "localhost"
#define        SQLPORT 0

/*MYSQL		real_mysql, *mysql = NULL;*/
MYSQL		real_mysql;

extern MYSQL	*reconnect_sql_db(void);
extern int	init_sql_db(void);
extern int      append_sql_db(struct rule *, const u_quad_t *);
extern int      update_sql_db(const struct rule *, const u_quad_t *);
extern int	sql_billing(struct rule *, struct ip_fw *);

#endif  /* WITH_MYSQL */
