import fs from 'fs';

try {
  if (fs.existsSync('dist/index.html')) {
    fs.copyFileSync('dist/index.html', 'dist/404.html');
    fs.writeFileSync('dist/.nojekyll', '');
    console.log('GitHub Pages static assets created: dist/404.html and dist/.nojekyll');
  }
} catch (err) {
  console.warn('Postbuild script warning:', err);
}
