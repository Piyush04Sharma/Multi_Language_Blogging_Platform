<?php
/**
 * Language Switcher Component
 * 
 * This file contains the HTML and JavaScript for the language switcher.
 */

// Include the language configuration
require_once __DIR__ . '/../config/languages.php';

// Get the current language
$current_lang = getCurrentLanguage();

// Get the current page URL without the language parameter
$current_url = $_SERVER['REQUEST_URI'];
$current_url = preg_replace('/[?&]lang=[^&]+/', '', $current_url);
$current_url = rtrim($current_url, '?&');

// Add a question mark or ampersand depending on whether there are other parameters
$param_separator = (strpos($current_url, '?') !== false) ? '&' : '?';
?>

<!-- Language Switcher -->
<div class="language-selector me-lg-3">
    <select id="language-selector" class="form-select" onchange="changeLanguage(this.value)" aria-label="<?php echo __('select_language', 'en'); ?>">
        <?php foreach ($supported_languages as $code => $language): ?>
            <option value="<?php echo $code; ?>" <?php echo ($code === $current_lang) ? 'selected' : ''; ?>>
                <?php echo $language['name']; ?>
            </option>
        <?php endforeach; ?>
    </select>
</div>

<script>
/**
 * Change the language and redirect to the same page with the new language
 * 
 * @param {string} lang The language code
 */
function changeLanguage(lang) {
    // Get the current URL without the language parameter
    const currentUrl = window.location.href;
    const urlWithoutLang = currentUrl.replace(/[?&]lang=[^&]+/, '');
    
    // Add a question mark or ampersand depending on whether there are other parameters
    const paramSeparator = urlWithoutLang.includes('?') ? '&' : '?';
    
    // Redirect to the same page with the new language
    window.location.href = urlWithoutLang + paramSeparator + 'lang=' + lang;
}
</script> 