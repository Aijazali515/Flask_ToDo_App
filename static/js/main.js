document.addEventListener('DOMContentLoaded', () => {
  const toggleButtons = document.querySelectorAll('.toggle-btn');
  toggleButtons.forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      const id = btn.getAttribute('data-id');
      if (!id) return;
      btn.disabled = true;
      try {
        const res = await fetch(`/task/${id}/toggle`, {
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-CSRFToken': window.CSRF_TOKEN || ''
          },
          body: JSON.stringify({})
        });
        const data = await res.json();
        if (data && data.ok) {
          const active = !!data.is_active;
          const icon = btn.querySelector('i');
          const text = btn.querySelector('.toggle-text');
          const badge = document.getElementById(`status-badge-${id}`);

          if (active) {
            btn.classList.remove('btn-outline-success');
            btn.classList.add('btn-outline-secondary');
            if (icon) { icon.classList.remove('bi-toggle-off'); icon.classList.add('bi-toggle-on'); }
            if (text) { text.textContent = 'Active'; }
            if (badge) { badge.textContent = 'Active'; badge.classList.remove('bg-secondary'); badge.classList.add('bg-success'); }
          } else {
            btn.classList.remove('btn-outline-secondary');
            btn.classList.add('btn-outline-success');
            if (icon) { icon.classList.remove('bi-toggle-on'); icon.classList.add('bi-toggle-off'); }
            if (text) { text.textContent = 'Inactive'; }
            if (badge) { badge.textContent = 'Inactive'; badge.classList.remove('bg-success'); badge.classList.add('bg-secondary'); }
          }
        }
      } catch (err) {
        console.error('Toggle failed', err);
        alert('Failed to toggle. Please refresh and try again.');
      } finally {
        btn.disabled = false;
      }
    });
  });
});
