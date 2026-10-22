/** 扫描静态页面与 JS 里的 Tailwind 类，本地预编译成 public/css/tailwind.css */
export default {
  content: ['./public/**/*.html', './public/js/**/*.js'],
  // 与参考项目（aegis-vault）使用的 Play CDN 默认配置保持一致，只额外把 safelist 收窄
  theme: { extend: {} },
  corePlugins: { preflight: true },
  plugins: [],
};
