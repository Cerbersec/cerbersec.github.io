---
title: Contact
icon: fa-envelope
order: 3
---

<p>If you have a question, comment or concern, don't hesitate to send me a message!</p>

<form method="post" action="https://formspree.io/{{ site.email }}">
  <div class="row">
    <div class="6u 12u$(mobile)"><input type="text" name="name" placeholder="Name" /></div>
    <div class="6u$ 12u$(mobile)"><input type="text" name="email" placeholder="Email" /></div>
    <div class="12u$">
      <textarea name="message" placeholder="Message"></textarea>
    </div>
    <div class="12u$">
      <input type="submit" value="Send Message" />
    </div>
  </div>
</form>