    (function(){
      const track = document.getElementById('tTrack');
      const prev  = document.getElementById('tPrev');
      const next  = document.getElementById('tNext');

      if(!track || !prev || !next) return;

      const slides = Array.from(track.children);
      let index = 0;

      function go(i){
        index = (i + slides.length) % slides.length; // loop
        track.style.transform = `translateX(-${index * 100}%)`;
      }

      prev.addEventListener('click', () => go(index - 1));
      next.addEventListener('click', () => go(index + 1));

      /* Optional: auto-advance every 7s; comment out if you don't want it
      let timer = setInterval(() => go(index + 1), 7000);
      track.addEventListener('mouseenter', () => clearInterval(timer));
      track.addEventListener('mouseleave', () => timer = setInterval(() => go(index + 1), 7000));
*/
      // Resize safety (if fonts change line breaks)
      window.addEventListener('resize', () => go(index));
    })();