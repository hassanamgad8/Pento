function googleSearch(type) {
    const targetDomain = document.getElementById('target').value;

    if (!targetDomain) {
        alert('Please enter a target domain.');
        return;
    }

    let searchQuery = 'site:' + targetDomain;
    let url;

    switch (type) {
        case 1:
            searchQuery += ' intitle:index.of';
            break;
        case 2:
            searchQuery += ' ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini';
            break;
        case 3:
            searchQuery += ' ext:sql | ext:dbf | ext:mdb';
            break;
        case 4:
            searchQuery += ' ext:log';
            break;
        case 5:
            searchQuery += ' ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup';
            break;
        case 6:
            searchQuery += ' inurl:login';
            break;
        case 7:
            searchQuery += ' intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"';
            break;
        case 8:
            searchQuery += ' ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv';
            break;
        case 9:
            searchQuery += ' ext:php intitle:phpinfo "published by the PHP Group"';
            break;
        case 10:
            searchQuery += ' inurl:wp- | inurl:wp-content | inurl:plugins | inurl:uploads | inurl:themes | inurl:download';
            break;
        case 11:
            searchQuery += ' inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor';
            break;
        case 12:
            searchQuery += ' inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config';
            break;
        case 13:
            searchQuery += ' inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http';
            break;
        case 14:
            searchQuery += ' ext:action | ext:struts | ext:do';
            break;
        case 15:
            url = 'https://www.google.com/search?q=' + encodeURIComponent('site:pastebin.com ' + targetDomain);
            window.open(url, '_blank');
            return;
        case 16:
            url = 'https://www.google.com/search?q=' + encodeURIComponent('site:linkedin.com employees ' + targetDomain);
            window.open(url, '_blank');
            return;
        case 17:
            url = 'https://www.google.com/search?q=' + encodeURIComponent('inurl:"/phpinfo.php" | inurl:".htaccess" | inurl:"/.git" ' + targetDomain + ' -github');
            window.open(url, '_blank');
            return;
        case 18:
            url = 'https://www.google.com/search?q=' + encodeURIComponent('site:*.' + targetDomain);
            window.open(url, '_blank');
            return;
        case 19:
            url = 'https://www.google.com/search?q=' + encodeURIComponent('site:*.*.' + targetDomain);
            window.open(url, '_blank');
            return;
        case 20:
            url = 'https://www.google.com/search?q=' + encodeURIComponent('inurl:wp-content | inurl:wp-includes ' + targetDomain);
            window.open(url, '_blank');
            return;
        case 21:
            url = 'https://github.com/search?q=' + encodeURIComponent('"*.' + targetDomain + '"') + '&type=host';
            window.open(url, '_blank');
            return;
        case 22:
            url = 'http://' + targetDomain + '/crossdomain.xml';
            window.open(url, '_blank');
            return;
        case 23:
            url = 'http://threatcrowd.org/domain.php?domain=' + targetDomain;
            window.open(url, '_blank');
            return;
        case 24:
            url = 'https://www.google.com/search?q=' + encodeURIComponent('+inurl:' + targetDomain + ' +ext:swf');
            window.open(url, '_blank');
            return;
        case 25:
            url = 'https://yandex.com/search/?text=' + encodeURIComponent('site:' + targetDomain + ' mime:swf');
            window.open(url, '_blank');
            return;
        case 26:
            url = 'https://web.archive.org/cdx/search?url=' + encodeURIComponent(targetDomain) + '/&matchType=domain&collapse=urlkey&output=text&fl=original&filter=urlkey:.*swf&limit=100000&_=1507209148310';
            window.open(url, '_blank');
            return;
        case 27:
            url = 'https://web.archive.org/cdx/search?url=' + encodeURIComponent(targetDomain) + '/&matchType=domain&collapse=urlkey&output=text&fl=original&filter=mimetype:application/x-shockwave-flash&limit=100000&_=1507209148310';
            window.open(url, '_blank');
            return;
        case 28:
            url = 'https://web.archive.org/web/*/(.' + encodeURIComponent(targetDomain) + ')';
            window.open(url, '_blank');
            return;
        case 29:
            url = 'https://web.archive.org/web/*/' + encodeURIComponent(targetDomain) + '/*';
            window.open(url, '_blank');
            return;
        case 30:
            url = 'https://crt.sh/?q=%25.' + targetDomain;
            window.open(url, '_blank');
            return;
        case 31:
            url = 'https://www.openbugbounty.org/search/?search=' + encodeURIComponent(targetDomain) + '&type=host';
            window.open(url, '_blank');
            return;
        case 32:
            url = 'https://www.reddit.com/search/?q=' + encodeURIComponent(targetDomain) + '&source=recent';
            window.open(url, '_blank');
            return;
        case 33:
            url = 'http://wwwb-dedup.us.archive.org:8083/cdx/search?url=' + encodeURIComponent(targetDomain) + '/&matchType=domain&collapse=digest&output=text&fl=original,timestamp&filter=urlkey:.*wp[-].*&limit=1000000&xx=';
            window.open(url, '_blank');
            return;
        case 34:
            url = 'https://censys.io/ipv4?q=' + targetDomain;
            window.open(url, '_blank');
            return;
        case 35:
            url = 'https://censys.io/domain?q=' + targetDomain;
            window.open(url, '_blank');
            return;
        case 36:
            url = 'https://censys.io/certificates?q=' + targetDomain;
            window.open(url, '_blank');
            return;
        case 37:
            url = 'https://www.shodan.io/search?query=' + targetDomain;
            window.open(url, '_blank');
            return;
        case 38:
            searchQuery += ' inurl:"/geoserver/ows?service=wfs"';
            break;
        case 39:
            searchQuery += ' intext:"ArcGIS REST Services Directory" intitle:"Folder: /"';
            break;
        case 40:
            searchQuery += ' inurl:/wp-content/uploads/wpo_wcpdf';
            break;
        case 41:
            searchQuery += ' intitle:"index of "main.yml"';
            break;
        case 42:
            searchQuery += ' inurl:/admin.aspx';
            break;
        case 43:
            searchQuery += ' inurl:/wp-content/uploads/wpo_wcpdf';
            break;
        case 44:
            searchQuery += ' inurl:uploadimage.php';
            break;
        case 45:
            searchQuery += ' inurl:*/wp-content/plugins/contact-form-7/';
            break;
        case 46:
            searchQuery += ' intitle:index.of conf.php';
            break;
        case 47:
            searchQuery += ' intitle:"Sharing API Info"';
            break;
        case 48:
            searchQuery += ' intitle:"Index of" inurl:/backup/ "admin.zip"';
            break;
        case 49:
            searchQuery += ' intitle:"index of" github-api';
            break;
        case 50:
            searchQuery += ' inurl:wp-content/uploads/wcpa_uploads';
            break;
        case 51:
            searchQuery += ' inurl:user intitle:"Drupal" intext:"Log in" -"powered by"';
            break;
        case 52:
            searchQuery += ' inurl: /libraries/joomla/database/';
            break;
        case 53:
            searchQuery += ' inurl:"php?sql=select" ext:php';
            break;
        case 54:
            searchQuery += ' inurl:"wp-content" intitle:"index.of" intext:wp-config.php';
            break;
        case 55:
            searchQuery += ' intext:"index of" inurl:json-rpc';
            break;
        case 56:
            searchQuery += ' intitle:"index of" "download.php?file="';
            break;
        case 57:
            searchQuery += ' intext:"index of" inurl:jwks-rsa';
            break;
        case 58:
            searchQuery += ' inurl:"wp-content" intitle:"index.of" intext:backup"';
            break;
        case 59:
            searchQuery += ' intitle:index.of conf.mysql';
            break;
        case 60:
            searchQuery += ' intitle:"index of" "users.yml" | "admin.yml" | "config.yml"';
            break;
        case 61:
            searchQuery += ' intitle:"index of" "docker-compose.yml"';
            break;
        case 62:
            searchQuery += ' intext:pom.xml intitle:"index of /"';
            break;
        case 63:
            searchQuery += ' intext:"Index of" intext:"/etc"';
            break;
        case 64:
            searchQuery += ' "sql" "parent" intitle:index.of -injection';
            break;
        default:
            alert('Invalid option.');
            return;
    }

    url = 'https://www.google.com/search?q=' + encodeURIComponent(searchQuery);
    window.open(url, '_blank');
} 