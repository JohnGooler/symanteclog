DROP TABLE IF EXISTS `ip_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ip_details` (
  `id` int NOT NULL AUTO_INCREMENT,
  `attackerip` varchar(15) NOT NULL,
  `addedtofirewall` varchar(5) NOT NULL,
  `createdat` varchar(10) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `attackerip_UNIQUE` (`attackerip`)
) ENGINE=InnoDB AUTO_INCREMENT=2875 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
