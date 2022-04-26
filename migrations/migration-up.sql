CREATE TABLE `api_login`
(
    `username` VARCHAR (130) NOT NULL PRIMARY KEY,
    `passwordHash` VARCHAR (255) NOT NULL,
    `role` VARCHAR (100) NULL,
    `timeExpired` DATETIME NOT NULL
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;
