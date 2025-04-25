<?php
/**
 * Database Configuration
 * 
 * This file contains the database configuration for the multilingual blogging platform.
 */

// Database credentials
$db_host = 'localhost';
$db_name = 'multilingual_blog';
$db_user = 'root';
$db_pass = '';

// Create a database connection
function getDbConnection() {
    global $db_host, $db_name, $db_user, $db_pass;
    
    try {
        $conn = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        return $conn;
    } catch(PDOException $e) {
        die("Connection failed: " . $e->getMessage());
    }
}

/**
 * Initialize the database and create tables if they don't exist
 */
function initializeDatabase() {
    global $db_host, $db_name, $db_user, $db_pass;
    
    try {
        // Connect to MySQL without selecting a database
        $conn = new PDO("mysql:host=$db_host", $db_user, $db_pass);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Create the database if it doesn't exist
        $conn->exec("CREATE DATABASE IF NOT EXISTS `$db_name` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        
        // Select the database
        $conn->exec("USE `$db_name`");
        
        // Create users table
        $conn->exec("CREATE TABLE IF NOT EXISTS `users` (
            `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
            `username` VARCHAR(50) NOT NULL,
            `email` VARCHAR(100) NOT NULL,
            `password` VARCHAR(255) NOT NULL,
            `first_name` VARCHAR(50) DEFAULT NULL,
            `last_name` VARCHAR(50) DEFAULT NULL,
            `bio` TEXT DEFAULT NULL,
            `avatar` VARCHAR(255) DEFAULT NULL,
            `role` ENUM('admin', 'author', 'user') NOT NULL DEFAULT 'user',
            `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (`id`),
            UNIQUE KEY `username` (`username`),
            UNIQUE KEY `email` (`email`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        
        // Create categories table
        $conn->exec("CREATE TABLE IF NOT EXISTS `categories` (
            `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
            `name` VARCHAR(100) NOT NULL,
            `slug` VARCHAR(100) NOT NULL,
            `description` TEXT DEFAULT NULL,
            `parent_id` INT(11) UNSIGNED DEFAULT NULL,
            `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (`id`),
            UNIQUE KEY `slug` (`slug`),
            KEY `parent_id` (`parent_id`),
            CONSTRAINT `categories_ibfk_1` FOREIGN KEY (`parent_id`) REFERENCES `categories` (`id`) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        
        // Create posts table (base table for multilingual posts)
        $conn->exec("CREATE TABLE IF NOT EXISTS `posts` (
            `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
            `user_id` INT(11) UNSIGNED NOT NULL,
            `category_id` INT(11) UNSIGNED DEFAULT NULL,
            `status` ENUM('draft', 'published', 'private') NOT NULL DEFAULT 'draft',
            `featured_image` VARCHAR(255) DEFAULT NULL,
            `comment_status` ENUM('open', 'closed') NOT NULL DEFAULT 'open',
            `comment_count` INT(11) NOT NULL DEFAULT '0',
            `view_count` INT(11) NOT NULL DEFAULT '0',
            `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (`id`),
            KEY `user_id` (`user_id`),
            KEY `category_id` (`category_id`),
            CONSTRAINT `posts_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
            CONSTRAINT `posts_ibfk_2` FOREIGN KEY (`category_id`) REFERENCES `categories` (`id`) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        
        // Create post_translations table (for multilingual content)
        $conn->exec("CREATE TABLE IF NOT EXISTS `post_translations` (
            `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
            `post_id` INT(11) UNSIGNED NOT NULL,
            `language` VARCHAR(5) NOT NULL,
            `title` VARCHAR(255) NOT NULL,
            `slug` VARCHAR(255) NOT NULL,
            `content` LONGTEXT NOT NULL,
            `excerpt` TEXT DEFAULT NULL,
            `meta_title` VARCHAR(255) DEFAULT NULL,
            `meta_description` TEXT DEFAULT NULL,
            `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (`id`),
            UNIQUE KEY `post_language` (`post_id`, `language`),
            UNIQUE KEY `slug_language` (`slug`, `language`),
            KEY `post_id` (`post_id`),
            CONSTRAINT `post_translations_ibfk_1` FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        
        // Create tags table
        $conn->exec("CREATE TABLE IF NOT EXISTS `tags` (
            `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
            `name` VARCHAR(100) NOT NULL,
            `slug` VARCHAR(100) NOT NULL,
            `description` TEXT DEFAULT NULL,
            `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (`id`),
            UNIQUE KEY `slug` (`slug`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        
        // Create post_tags table (many-to-many relationship)
        $conn->exec("CREATE TABLE IF NOT EXISTS `post_tags` (
            `post_id` INT(11) UNSIGNED NOT NULL,
            `tag_id` INT(11) UNSIGNED NOT NULL,
            PRIMARY KEY (`post_id`, `tag_id`),
            KEY `tag_id` (`tag_id`),
            CONSTRAINT `post_tags_ibfk_1` FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) ON DELETE CASCADE,
            CONSTRAINT `post_tags_ibfk_2` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        
        // Create comments table
        $conn->exec("CREATE TABLE IF NOT EXISTS `comments` (
            `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
            `post_id` INT(11) UNSIGNED NOT NULL,
            `user_id` INT(11) UNSIGNED DEFAULT NULL,
            `parent_id` INT(11) UNSIGNED DEFAULT NULL,
            `author` VARCHAR(100) DEFAULT NULL,
            `email` VARCHAR(100) DEFAULT NULL,
            `url` VARCHAR(200) DEFAULT NULL,
            `ip` VARCHAR(100) DEFAULT NULL,
            `content` TEXT NOT NULL,
            `status` ENUM('approved', 'pending', 'spam') NOT NULL DEFAULT 'pending',
            `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (`id`),
            KEY `post_id` (`post_id`),
            KEY `user_id` (`user_id`),
            KEY `parent_id` (`parent_id`),
            CONSTRAINT `comments_ibfk_1` FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) ON DELETE CASCADE,
            CONSTRAINT `comments_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
            CONSTRAINT `comments_ibfk_3` FOREIGN KEY (`parent_id`) REFERENCES `comments` (`id`) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        
        return true;
    } catch(PDOException $e) {
        die("Database initialization failed: " . $e->getMessage());
    }
} 