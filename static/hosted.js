(() => {
  const token = document.querySelector('meta[name="klar-csrf"]').content;
  const safe = new Set(['GET', 'HEAD', 'OPTIONS']);

  function bindForm(form, button) {
    const method = button?.getAttribute('formmethod') || form.method;
    const action = button?.getAttribute('formaction') || form.action;
    if (safe.has(method.toUpperCase()) || new URL(action, location.href).origin !== location.origin) return;
    let field = form.querySelector('input[name="_klar_csrf"]');
    if (!field) {
      field = document.createElement('input');
      field.type = 'hidden';
      field.name = '_klar_csrf';
      form.append(field);
    }
    field.value = token;
  }

  document.addEventListener('submit', event => bindForm(event.target, event.submitter), true);
  const submit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function () {
    bindForm(this);
    return submit.call(this);
  };

  const fetch = window.fetch.bind(window);
  window.fetch = (input, options) => {
    const method = (options?.method || input.method || 'GET').toUpperCase();
    const url = new URL(input instanceof Request ? input.url : input, location.href);
    if (safe.has(method) || url.origin !== location.origin) return fetch(input, options);
    const headers = new Headers(options?.headers || input.headers);
    headers.set('X-Klar-CSRF', token);
    return fetch(input, {...options, headers});
  };
})();
