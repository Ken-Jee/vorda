
(function(){var t=localStorage.getItem('vorda-theme');if(t)document.documentElement.dataset.theme=t;})();
document.addEventListener('DOMContentLoaded',function(){
var b=document.querySelector('.theme');if(b)b.addEventListener('click',function(){var d=document.documentElement,
dark=d.dataset.theme?d.dataset.theme==='dark':matchMedia('(prefers-color-scheme: dark)').matches;d.dataset.theme=dark?'light':'dark';localStorage.setItem('vorda-theme',d.dataset.theme);});
var tip=document.getElementById('tip');
function show(e){var el=e.target.closest('[data-tip]');if(!el){tip.style.display='none';return;}
tip.textContent=el.getAttribute('data-tip');tip.style.display='block';var r=el.getBoundingClientRect(),w=tip.offsetWidth,h=tip.offsetHeight;
var x=Math.min(Math.max(8,r.left+r.width/2-w/2),innerWidth-w-8),y=r.top-h-8;if(y<8)y=r.bottom+8;tip.style.left=x+'px';tip.style.top=y+'px';}
document.addEventListener('pointerover',show);document.addEventListener('click',show);
document.querySelectorAll('[data-copy]').forEach(function(c){c.addEventListener('click',function(){navigator.clipboard&&navigator.clipboard.writeText(c.dataset.copy);c.textContent='Copied';});});
});
