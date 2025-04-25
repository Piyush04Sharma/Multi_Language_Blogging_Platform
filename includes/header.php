<?php
/**
 * Header Include
 * 
 * This file contains the header HTML that will be included in all pages.
 */

// Start the session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Include the language configuration and translations
require_once __DIR__ . '/../config/languages.php';
require_once __DIR__ . '/../config/translations.php';

// Get the current language
$current_lang = getCurrentLanguage();

// Get the language direction
$dir = getLanguageDirection($current_lang);

// Set the HTML lang attribute
$html_lang = $current_lang;

// Get the current page name
$current_page = basename($_SERVER['PHP_SELF'], '.php');
?>
<!doctype html>
<html lang="<?php echo $html_lang; ?>" dir="<?php echo $dir; ?>">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title><?php echo __('site_title'); ?></title>
    
    <link href="//fonts.googleapis.com/css2?family=Poppins:ital,wght@0,300;0,400;0,700;1,400;1,600&display=swap" rel="stylesheet">
    
    <link rel="stylesheet" href="assets/css/style-starter.css">
    
    <!-- Add RTL stylesheet for RTL languages -->
    <?php if ($dir === 'rtl'): ?>
    <link rel="stylesheet" href="assets/css/rtl.css">
    <?php endif; ?>
</head>

<body>

<header id="site-header" class="fixed-top">
    <div class="container">
        <nav class="navbar navbar-expand-lg navbar-light stroke py-lg-0">
            <h1><a class="navbar-brand pe-xl-5 pe-lg-4" href="index.php">
                    <span class="sublog">Multiligno</span>Blog
                </a></h1>
            <!-- Toggle button for responsive navbar -->
            <button class="navbar-toggler collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#navbarScroll" aria-controls="navbarScroll" aria-expanded="false" aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon fa icon-expand fa-bars"></span>
                    <span class="navbar-toggler-icon fa icon-close fa-times"></span>
                </button>
            <div class="collapse navbar-collapse" id="navbarScroll">
                <!-- Navbar Items -->
                <ul class="navbar-nav me-lg-auto my-2 my-lg-0 navbar-nav-scroll">
                    <li class="nav-item">
                        <a class="nav-link <?php echo ($current_page === 'index') ? 'active' : ''; ?>" aria-current="page" href="index.php"><?php echo __('home'); ?></a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo ($current_page === 'about') ? 'active' : ''; ?>" href="about.php"><?php echo __('about'); ?></a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo ($current_page === 'services') ? 'active' : ''; ?>" href="services.php"><?php echo __('services'); ?></a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?php echo ($current_page === 'contact') ? 'active' : ''; ?>" href="contact.php"><?php echo __('contact'); ?></a>
                    </li>
                </ul>

                <!-- Search and Register Button -->
                <ul class="navbar-nav search-right mt-lg-0 mt-2">
                    <li class="nav-item" title="<?php echo __('search'); ?>"><a href="#search" class="search-search">
                            <span class="fas fa-search" aria-hidden="true"></span></a></li>
                    <li class="nav-item me-lg-3">
                        <a href="#" class="phone-btn btn btn-primary btn-style d-none d-lg-block btn-style ms-2"><?php echo __('register'); ?></a>
                    </li>
                </ul>

                <!-- Include the language switcher -->
                <?php include __DIR__ . '/language-switcher.php'; ?>

                <!-- Search Popup -->
                <div id="search" class="w3lpop-overlay">
                    <div class="w3lpopup">
                        <form action="#formsearch" method="GET" class="d-sm-flex">
                            <input class="form-control me-2" type="search" placeholder="<?php echo __('search_placeholder'); ?>" aria-label="<?php echo __('search'); ?>" required="">
                            <button class="btn btn-style btn-primary" type="submit"><?php echo __('search'); ?></button>
                            <a class="close" href="#formsearch">&times;</a>
                        </form>
                    </div>
                </div>
            </div>
        </nav>
    </div>
</header> 