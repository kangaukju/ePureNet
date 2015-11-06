[web]
shop
edu
com
soc
person
media
living
trip
culture
religion
game
entertain
leisure
economy


[application]
certificate
p2p
messenger
remote
protocol
game
email
nettv








CREATE TABLE `policy`.`game` (
  `name` VARCHAR(128) NOT NULL DEFAULT '',
  `agent1` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent2` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent3` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent4` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent5` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent6` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent7` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent8` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent9` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent10` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent11` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent12` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent13` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent14` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent15` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent16` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent17` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent18` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent19` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent20` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent21` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent22` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent23` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent24` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent25` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent26` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent27` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent28` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent29` enum('Y','N') NOT NULL DEFAULT 'N',
  `agent30` enum('Y','N') NOT NULL DEFAULT 'N',
  PRIMARY KEY (`name`)
)
ENGINE = MyISAM;

#[web]
CREATE TABLE `policy`.`shop` select * from `policy`.`game`;
CREATE TABLE `policy`.`edu` select * from `policy`.`game`;
CREATE TABLE `policy`.`com` select * from `policy`.`game`;
CREATE TABLE `policy`.`soc` select * from `policy`.`game`;
CREATE TABLE `policy`.`person` select * from `policy`.`game`;
CREATE TABLE `policy`.`living` select * from `policy`.`game`;
CREATE TABLE `policy`.`trip` select * from `policy`.`game`;
CREATE TABLE `policy`.`culture` select * from `policy`.`game`;
CREATE TABLE `policy`.`religion` select * from `policy`.`game`;
CREATE TABLE `policy`.`entertain` select * from `policy`.`game`;
CREATE TABLE `policy`.`leisure` select * from `policy`.`game`;
CREATE TABLE `policy`.`economy` select * from `policy`.`game`;


#[application]
CREATE TABLE `policy`.`certificate` select * from `policy`.`game`;
CREATE TABLE `policy`.`p2p` select * from `policy`.`game`;
CREATE TABLE `policy`.`messenger` select * from `policy`.`game`;
CREATE TABLE `policy`.`remote` select * from `policy`.`game`;
CREATE TABLE `policy`.`protocol` select * from `policy`.`game`;
CREATE TABLE `policy`.`email` select * from `policy`.`game`;
CREATE TABLE `policy`.`internettv` select * from `policy`.`game`;



#[ip]
CREATE TABLE `policy`.`ip` select * from `policy`.`game`;

#[keyword]
CREATE TABLE `policy`.`keyword` select * from `policy`.`game`;