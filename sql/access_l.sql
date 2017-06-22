GRANT USAGE ON ipa.* to ipauser@localhost;
GRANT SELECT,UPDATE,INSERT,DELETE,CREATE ON ipa.* to ipauser@localhost;
SET PASSWORD FOR "ipauser"@"localhost"=PASSWORD("ipauser");



