-- Active: 1712951636808@@localhost@3306@UNSEEN_DB
-- @block CREATE CUSTOMER TABLE
CREATE TABLE IF NOT EXISTS `USERS` (
    `userId` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `avatar` TEXT,
    `fullName` VARCHAR(256) NOT NULL,
    `bio` TEXT,
    `userName` VARCHAR(256) NOT NULL, 
    `password` TEXT NOT NULL, 
    `homeLocation` VARCHAR(128) NOT NULL,
    `homeCoordinate` TEXT NOT NULL,
    `currentLocation` VARCHAR(128) NOT NULL,
    `currentCoordinate` TEXT NOT NULL,
    `rank` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `rankGroup` ENUM('BRASS','SILVER','GOLD','DIAMOND','PLATINUM') NOT NULL DEFAULT 0,
    `totalCubeCollected` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `totalQuestPlayed` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `totalQuestCreated` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `totalFollowers` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `totalFollowees` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `deviceId` TEXT NOT NULL,
    `deviceName` TEXT NOT NULL,
    `fcmToken` TEXT NOT NULL,
    `languageCode` VARCHAR(4) NOT NULL DEFAULT 'en',
    `createdAt` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updatedAt` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `status` ENUM(
        'ACTIVE',
        'BLOCKED'
    ) NOT NULL DEFAULT 'ACTIVE',
    -- CONSTRAINTS
    PRIMARY KEY pk_userid (userId),
    UNIQUE KEY uk_username (userName),
    INDEX idx_fullname (fullName),
    INDEX idx_rank (`rank`)
) ENGINE = InnoDB;

-- @block SET AUTO AUTO_INCREMENT INITIAL VALUE 1001
ALTER TABLE `USERS` AUTO_INCREMENT = 1001;