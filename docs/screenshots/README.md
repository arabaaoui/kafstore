# Screenshots

This directory contains screenshots of the Kafstore interface for documentation purposes.

## Required Screenshots

To complete the documentation, please capture and add the following screenshots:

1. **kafstore-upload.png** - Upload screen showing the 3 file upload boxes (CA Chain, Bundle, Private Key)
2. **kafstore-config.png** - Configuration section with alias and separate password fields
3. **kafstore-generate.png** - Generation screen with success message and download options

## How to Capture Screenshots

1. Start the Kafstore application:
   ```bash
   docker run -d -p 5000:5000 --name kafstore kafstore
   ```

2. Open http://localhost:5000 in your browser

3. Capture the following screens:
   - **Upload Screen**: Main interface with empty upload boxes
   - **Config Screen**: After uploading files, showing the configuration form
   - **Generate Screen**: After generating keystores, showing success message and download button

4. Save the screenshots in this directory with the names listed above

## Screenshot Guidelines

- Use a resolution of at least 1920x1080
- Capture the full interface or relevant sections
- Use dark mode if available
- Ensure no sensitive information is visible
- PNG format preferred for better quality
