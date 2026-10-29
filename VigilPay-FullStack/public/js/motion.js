const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const finePointer = window.matchMedia("(pointer: fine)");
let revealObserver;
let particleFrame;

export function initMotion() {
  initLoader();
  initCursorGlow();
  initSecurityCanvas();
  initRippleEffects();
  initHeroParallax();
  initCounters();
  initRevealObserver();
  const main=document.querySelector("#main");
  if(main)new MutationObserver(()=>requestAnimationFrame(refreshMotionTargets)).observe(main,{childList:true,subtree:true});
  document.documentElement.classList.add("motion-ready");
}

function initLoader() {
  const loader = document.querySelector("#appLoader");
  const bar = document.querySelector("#loaderBar");
  const label = document.querySelector("#loaderText");
  if (!loader) return;
  if (sessionStorage.getItem("vigilpay_intro_seen") || reduceMotion.matches) {
    loader.remove();
    return;
  }
  const messages = ["Starting protection systems…","Loading risk intelligence…","Securing your session…","Vigil is ready."];
  const start = performance.now();
  const duration = 1250;
  const tick = (time) => {
    const progress = Math.min(1, (time - start) / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    bar.style.width = `${Math.round(eased * 100)}%`;
    label.textContent = messages[Math.min(messages.length - 1, Math.floor(progress * messages.length))];
    if (progress < 1) requestAnimationFrame(tick);
    else {
      sessionStorage.setItem("vigilpay_intro_seen", "1");
      setTimeout(() => { loader.classList.add("loader-exit"); setTimeout(() => loader.remove(), 650); }, 180);
    }
  };
  requestAnimationFrame(tick);
}

function initCursorGlow() {
  const glow = document.querySelector("#cursorGlow");
  if (!glow || !finePointer.matches || reduceMotion.matches) return;
  let currentX = innerWidth / 2, currentY = innerHeight / 2, targetX = currentX, targetY = currentY;
  document.addEventListener("pointermove", (event) => { targetX = event.clientX; targetY = event.clientY; glow.classList.add("visible"); }, { passive:true });
  document.addEventListener("pointerleave", () => glow.classList.remove("visible"));
  const update = () => { currentX += (targetX-currentX)*.14; currentY += (targetY-currentY)*.14; glow.style.transform=`translate3d(${currentX}px,${currentY}px,0)`; requestAnimationFrame(update); };
  update();
}

function initSecurityCanvas() {
  const canvas = document.querySelector("#securityCanvas");
  if (!canvas || reduceMotion.matches || navigator.connection?.saveData) return;
  const context = canvas.getContext("2d");
  let width, height, particles=[];
  const resize = () => {
    const ratio=Math.min(devicePixelRatio||1,2); width=innerWidth; height=innerHeight; canvas.width=width*ratio; canvas.height=height*ratio; canvas.style.width=`${width}px`; canvas.style.height=`${height}px`; context.setTransform(ratio,0,0,ratio,0,0);
    const count=Math.min(55,Math.max(24,Math.floor(width/28))); particles=Array.from({length:count},()=>({x:Math.random()*width,y:Math.random()*height,vx:(Math.random()-.5)*.18,vy:(Math.random()-.5)*.18,r:Math.random()*1.4+.4}));
  };
  const draw=()=>{ context.clearRect(0,0,width,height); context.fillStyle="rgba(73,239,181,.27)"; for(const p of particles){p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>width)p.vx*=-1;if(p.y<0||p.y>height)p.vy*=-1;context.beginPath();context.arc(p.x,p.y,p.r,0,Math.PI*2);context.fill();} context.strokeStyle="rgba(73,239,181,.045)"; for(let i=0;i<particles.length;i++){for(let j=i+1;j<particles.length;j++){const a=particles[i],b=particles[j],d=Math.hypot(a.x-b.x,a.y-b.y);if(d<120){context.globalAlpha=1-d/120;context.beginPath();context.moveTo(a.x,a.y);context.lineTo(b.x,b.y);context.stroke();}}}context.globalAlpha=1;particleFrame=requestAnimationFrame(draw);};
  resize(); draw(); addEventListener("resize",resize,{passive:true}); document.addEventListener("visibilitychange",()=>{if(document.hidden)cancelAnimationFrame(particleFrame);else draw();});
}

function initRippleEffects() {
  document.addEventListener("pointerdown", (event) => {
    const target=event.target.closest(".button,.action-card,.nav-link,.emergency-grid button,.quiz-option");
    if(!target||reduceMotion.matches)return;
    const rect=target.getBoundingClientRect(), ripple=document.createElement("i");
    ripple.className="motion-ripple"; ripple.style.left=`${event.clientX-rect.left}px`; ripple.style.top=`${event.clientY-rect.top}px`; target.append(ripple); setTimeout(()=>ripple.remove(),650);
  });
}

function initHeroParallax() {
  const orbit=document.querySelector("#riskOrbit"); if(!orbit||!finePointer.matches||reduceMotion.matches)return;
  orbit.closest(".hero")?.addEventListener("pointermove",(event)=>{const rect=event.currentTarget.getBoundingClientRect();const x=(event.clientX-rect.left)/rect.width-.5,y=(event.clientY-rect.top)/rect.height-.5;orbit.style.transform=`perspective(700px) rotateX(${-y*7}deg) rotateY(${x*9}deg) translate3d(${x*8}px,${y*8}px,0)`;});
  orbit.closest(".hero")?.addEventListener("pointerleave",()=>orbit.style.transform="");
}

function initCounters() {
  const run=(element)=>{const end=Number(element.dataset.counter||0),suffix=element.dataset.suffix||"";if(reduceMotion.matches){element.textContent=`${end}${suffix}`;return;}const start=performance.now(),duration=900;const step=(time)=>{const p=Math.min(1,(time-start)/duration),eased=1-Math.pow(1-p,3);element.textContent=`${Math.round(end*eased)}${suffix}`;if(p<1)requestAnimationFrame(step);};requestAnimationFrame(step);};
  document.querySelectorAll("[data-counter]").forEach(run);
}

function initRevealObserver() {
  if(reduceMotion.matches)return;
  revealObserver=new IntersectionObserver((entries)=>entries.forEach((entry)=>{if(entry.isIntersecting){entry.target.classList.add("revealed");revealObserver.unobserve(entry.target);}}),{threshold:.08,rootMargin:"0px 0px -30px"});
}

export function refreshMotionTargets() {
  if(!revealObserver)return;
  document.querySelectorAll(".page.active .panel,.page.active .action-card,.page.active .guide-card,.page.active .stat-grid article,.page.active .report-card,.page.active .emergency-grid button").forEach((element,index)=>{if(element.dataset.motionBound)return;element.dataset.motionBound="1";element.classList.add("motion-reveal");element.style.setProperty("--reveal-delay",`${Math.min(index,8)*45}ms`);revealObserver.observe(element);if(finePointer.matches)bindTilt(element);});
}

function bindTilt(element) {
  if(reduceMotion.matches||element.matches(".tool-panel,.result-panel,.chart-panel,.alert-panel,.safety-meter-panel"))return;
  element.addEventListener("pointermove",(event)=>{const rect=element.getBoundingClientRect(),x=(event.clientX-rect.left)/rect.width-.5,y=(event.clientY-rect.top)/rect.height-.5;element.style.setProperty("--tilt-x",`${-y*3.5}deg`);element.style.setProperty("--tilt-y",`${x*4.5}deg`);element.style.setProperty("--shine-x",`${(x+.5)*100}%`);element.style.setProperty("--shine-y",`${(y+.5)*100}%`);});
  element.addEventListener("pointerleave",()=>{element.style.removeProperty("--tilt-x");element.style.removeProperty("--tilt-y");});
}

export function animateRouteChange(swap) {
  const progress=document.querySelector("#routeProgress"); progress?.classList.add("active");
  if(document.startViewTransition&&!reduceMotion.matches)document.startViewTransition(swap);else swap();
  setTimeout(()=>progress?.classList.remove("active"),460);
}

export function setButtonLoading(button, loading, label) {
  if(!button)return; button.disabled=loading; button.classList.toggle("is-loading",loading); button.innerHTML=loading?`<i class="button-spinner"></i><span>${label}</span>`:label;
}
