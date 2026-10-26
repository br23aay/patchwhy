-- NOTE (26 Oct): FIRST's order=!epss on this API now returns CVEs sorted by id, not by score, so the EPSS source filters with epss-gt=0.88 (944 rows) instead of "top 1000".
-- VERIFIED 21 Oct 2026 in Zetaris SQL Workspace. Run ONE statement at a time.
CREATE LIGHTNING DATABASE VULN_REST DESCRIBE BY "KEV and EPSS REST sources"

CREATE LIGHTNING REST TABLE epss_hi FROM VULN_REST REQUEST(endpoint "https://api.first.org/data/v1/epss?epss-gt=0.88&limit=1000", method "get", response_type "json", http_encoding "URLENCODED") HEADER () BODY ()

CREATE LIGHTNING REST TABLE kev_catalog FROM VULN_REST REQUEST(endpoint "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json", method "get", response_type "json", http_encoding "URLENCODED") HEADER () BODY ()

CREATE SCHEMASTORE CONTAINER vulnstore

CREATE SCHEMASTORE VIEW kev WITH CONTAINER vulnstore AS SELECT v.cveID AS cve, v.vendorProject AS vendor, v.product AS product, v.vulnerabilityName AS vuln_name, v.dateAdded AS date_added, v.dueDate AS due_date, v.knownRansomwareCampaignUse AS ransomware FROM VULN_REST.kev_catalog LATERAL VIEW explode(vulnerabilities) AS v

CREATE SCHEMASTORE VIEW epss WITH CONTAINER vulnstore AS SELECT d.cve AS cve, CAST(d.epss AS DOUBLE) AS epss, CAST(d.percentile AS DOUBLE) AS percentile FROM VULN_REST.epss_hi LATERAL VIEW explode(data) AS d

SELECT k.cve, k.vendor, k.product, e.epss, e.percentile, k.ransomware, k.due_date FROM vulnstore.kev k JOIN vulnstore.epss e ON k.cve = e.cve ORDER BY e.epss DESC LIMIT 10

-- THIRD SOURCE (verified 22 Oct): synthetic asset inventory, see data/assets.csv
CREATE SCHEMASTORE VIEW assets WITH CONTAINER vulnstore AS SELECT * FROM VALUES ('A001','fw-edge-01','Palo Alto Networks','PAN-OS','production','yes',5,'Network','unpatched'), ('A002','fw-edge-02','Palo Alto Networks','PAN-OS','production','yes',5,'Network','patched'), ('A003','vpn-gw-01','Ivanti','Connect Secure and Policy Secure','production','yes',5,'Network','unpatched'), ('A004','mdm-01','Ivanti','Endpoint Manager Mobile (EPMM) and MobileIron Core','production','yes',3,'IT Ops','unpatched'), ('A005','wiki-01','Atlassian','Confluence Data Center and Server','production','yes',4,'Engineering','unpatched'), ('A006','wiki-stg','Atlassian','Confluence Data Center and Server','staging','no',1,'Engineering','unpatched'), ('A007','jira-01','Atlassian','Jira Server and Data Center','production','no',3,'Engineering','unpatched'), ('A008','chat-01','Ignite Realtime','Openfire','production','no',2,'IT Ops','unpatched'), ('A009','lb-01','IETF','HTTP/2','production','yes',4,'Platform','unpatched'), ('A010','lb-02','IETF','HTTP/2','production','yes',4,'Platform','patched'), ('A011','swg-01','Sophos','Web Appliance','production','yes',3,'Security','unpatched'), ('A012','mail-01','Microsoft','Exchange Server','production','yes',5,'IT Ops','unpatched'), ('A013','mail-02','Microsoft','Exchange Server','production','no',4,'IT Ops','patched'), ('A014','app-orders-01','Apache','Log4j2','production','yes',5,'Platform','unpatched'), ('A015','app-reports-01','Apache','Log4j2','production','no',2,'Data','unpatched'), ('A016','dev-sandbox-01','Apache','Log4j2','development','no',1,'Engineering','unpatched'), ('A017','vpn-gw-02','Ivanti','Connect Secure and Policy Secure','production','yes',5,'Network','patched') AS t(asset_id, hostname, vendor, product, environment, internet_facing, criticality, owner_team, patch_status)

-- THREE-WAY JOIN (verified 22 Oct, returns 15 rows)
SELECT a.asset_id, a.hostname, a.environment, a.internet_facing, a.criticality, k.cve, e.epss, k.ransomware, k.due_date FROM vulnstore.assets a JOIN vulnstore.kev k ON a.vendor = k.vendor AND a.product = k.product JOIN vulnstore.epss e ON k.cve = e.cve WHERE a.patch_status = 'unpatched' ORDER BY a.criticality DESC, e.epss DESC LIMIT 15
