'use strict';
const CACHE='gth-walk-v1.7';
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(c=>c.addAll(['/','/app.js','/walk.js','/viz.js','/style.css','/icon.svg','/manifest.webmanifest','/api/glossary']))));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k))))));
self.addEventListener('fetch',event=>{const url=new URL(event.request.url);if(url.origin!==self.location.origin||url.pathname.startsWith('/api/')&&url.pathname!=='/api/glossary'||url.pathname.startsWith('/proofs/'))return;event.respondWith(fetch(event.request).catch(()=>event.request.mode==='navigate'?caches.match('/'):caches.match(event.request)));});
