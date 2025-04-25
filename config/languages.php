<?php
/**
 * Language Configuration
 * 
 * This file contains the configuration for supported languages in the multilingual blogging platform.
 */

// Define supported languages
$supported_languages = [
    'en' => [
        'name' => 'English',
        'code' => 'en',
        'flag' => 'gb',
        'direction' => 'ltr'
    ],
    'es' => [
        'name' => 'Español',
        'code' => 'es',
        'flag' => 'es',
        'direction' => 'ltr'
    ],
    'fr' => [
        'name' => 'Français',
        'code' => 'fr',
        'flag' => 'fr',
        'direction' => 'ltr'
    ],
    'hi' => [
        'name' => 'हिंदी',
        'code' => 'hi',
        'flag' => 'in',
        'direction' => 'ltr'
    ],
    'ar' => [
        'name' => 'العربية',
        'code' => 'ar',
        'flag' => 'sa',
        'direction' => 'rtl'
    ]
];

// Default language
$default_language = 'en';

// Get current language from session or URL parameter
function getCurrentLanguage() {
    global $supported_languages, $default_language;
    
    // Check if language is set in session
    if (isset($_SESSION['language']) && array_key_exists($_SESSION['language'], $supported_languages)) {
        return $_SESSION['language'];
    }
    
    // Check if language is set in URL parameter
    if (isset($_GET['lang']) && array_key_exists($_GET['lang'], $supported_languages)) {
        $_SESSION['language'] = $_GET['lang'];
        return $_GET['lang'];
    }
    
    // Check browser language
    if (isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
        $browser_lang = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2);
        if (array_key_exists($browser_lang, $supported_languages)) {
            $_SESSION['language'] = $browser_lang;
            return $browser_lang;
        }
    }
    
    // Return default language
    return $default_language;
}

// Get language name by code
function getLanguageName($code) {
    global $supported_languages;
    
    if (array_key_exists($code, $supported_languages)) {
        return $supported_languages[$code]['name'];
    }
    
    return 'Unknown';
}

// Get language direction by code
function getLanguageDirection($code) {
    global $supported_languages;
    
    if (array_key_exists($code, $supported_languages)) {
        return $supported_languages[$code]['direction'];
    }
    
    return 'ltr';
} 