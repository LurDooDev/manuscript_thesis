/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './templates/**/*.{html,js}', // adjust this according to your template structure
    './static/**/*.{html,js}',     // if you have static files
  ],
  theme: {
    extend: {},
  },
  plugins: [],
};