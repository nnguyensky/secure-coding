import { useRef, useCallback, useSyncExternalStore } from 'react';

const query = '(prefers-reduced-motion: reduce)';
export function useReducedMotion() {
  return useSyncExternalStore(
    cb => { const m = window.matchMedia(query); m.addEventListener('change', cb); return () => m.removeEventListener('change', cb); },
    () => window.matchMedia(query).matches,
    () => false,
  );
}

// A card that leans toward the pointer in 3D, with a moving highlight.
// Purely presentational: it never moves under reduced motion or keyboard use.
export function TiltCard({ className = '', max = 9, children, ...rest }) {
  const ref = useRef(null);
  const reduced = useReducedMotion();
  const onMove = useCallback(e => {
    if (reduced || !ref.current) return;
    const r = ref.current.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width;
    const py = (e.clientY - r.top) / r.height;
    ref.current.style.setProperty('--ry', `${(px - 0.5) * 2 * max}deg`);
    ref.current.style.setProperty('--rx', `${(0.5 - py) * 2 * max}deg`);
    ref.current.style.setProperty('--gx', `${px * 100}%`);
    ref.current.style.setProperty('--gy', `${py * 100}%`);
  }, [reduced, max]);
  const onLeave = useCallback(() => {
    if (!ref.current) return;
    ref.current.style.setProperty('--rx', '0deg');
    ref.current.style.setProperty('--ry', '0deg');
  }, []);
  return (
    <div ref={ref} className={`tilt ${className}`} onPointerMove={onMove} onPointerLeave={onLeave} {...rest}>
      <div className="tilt-inner">{children}</div>
      <div className="tilt-glare" aria-hidden="true" />
    </div>
  );
}
