go get -u gorm.io/gen
go install gorm.io/gen/tools/gentool@latest

go run gentool.go -c "./gen.yml"

mysql -u root -p

CREATE USER 'unseen_user'@'localhost' IDENTIFIED BY 'unseen_pwd';

GRANT CREATE, ALTER, DROP, INSERT, UPDATE, DELETE, SELECT, REFERENCES, RELOAD on *.* TO 'unseen_user'@'localhost' WITH GRANT OPTION;

SHOW GRANTS FOR 'unseen_user'@'localhost';

FLUSH PRIVILEGES;

REVOKE CREATE, ALTER, DROP, INSERT, UPDATE, DELETE, SELECT, REFERENCES, RELOAD ON UNSEEN_DB FROM 'unseen_user'@'localhost';

DROP USER 'unseen_user'@'localhost';