const rows = {
  important: [['L','mint','Linh Nguyễn','Một ý tưởng cho dự án tiếp theo','Mình đã tổng hợp vài hướng mới. Cùng xem qua nhé?','09:41'],['M','peach','Minh Anh','Cà phê và câu chuyện thiết kế','Sáng thứ sáu bạn có rảnh không?','08:30'],['S','lilac','Studio Một','Bản thiết kế đã sẵn sàng','Một bước nữa để biến ý tưởng thành hiện thực.','Hôm qua']],
  news: [['D','mint','Design Notes','Một chút cảm hứng cho cuối tuần','Những câu chuyện thiết kế đáng dành thời gian.','07:00'],['C','peach','Cộng đồng sáng tạo','Tháng này, chúng ta cùng làm gì?','Workshop, góc đọc và vài ý tưởng mới.','Hôm qua']],
  calendar: [['M','peach','Minh Anh','Cà phê và câu chuyện thiết kế','Thứ sáu · 09:30–10:30 · Quán cà phê quen','09:30'],['S','mint','Studio Một','Cùng xem lại bản thiết kế','Thứ sáu · 14:00–15:00 · Cuộc họp trực tuyến','14:00']]
};
const tabs = [...document.querySelectorAll('[role="tab"]')];
function selectTab(tab) {
  tabs.forEach(item => { item.setAttribute('aria-selected', String(item === tab)); item.tabIndex = item === tab ? 0 : -1; });
  const panel = document.getElementById('mail-panel');
  panel.setAttribute('aria-labelledby', tab.id);
  panel.replaceChildren(...rows[tab.dataset.tab].map(([initial, color, sender, subject, preview, time]) => {
    const row = document.createElement('div'); row.className = 'mail-row';
    const avatar = document.createElement('span'); avatar.className = `avatar ${color}`; avatar.textContent = initial;
    const content = document.createElement('div');
    for (const [tag, text] of [['b', sender], ['strong', subject], ['p', preview]]) { const el = document.createElement(tag); el.textContent = text; content.append(el); }
    const date = document.createElement('span'); date.className = 'row-time'; date.textContent = time;
    row.append(avatar, content, date); return row;
  }));
  panel.classList.remove('panel-enter'); requestAnimationFrame(() => panel.classList.add('panel-enter'));
}
tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectTab(tab));
  tab.addEventListener('keydown', event => {
    let next;
    if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = tabs.length - 1;
    if (next !== undefined) { event.preventDefault(); tabs[next].focus(); selectTab(tabs[next]); }
  });
});
// Content stays visible without JavaScript or when reduced motion is requested.
if ('IntersectionObserver' in window && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
  const observer = new IntersectionObserver(entries => entries.forEach(entry => {
    if (entry.isIntersecting) { entry.target.classList.add('reveal'); observer.unobserve(entry.target); }
  }), { threshold: 0.12 });
  document.querySelectorAll('.demo, .feature-list article, .privacy-points article').forEach(el => observer.observe(el));
}
