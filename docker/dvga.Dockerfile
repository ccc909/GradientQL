# Monkey-patched DVGA, for use as a GradientQL test target.
#
# The stock dolevf/dvga serves via gevent's pywsgi.WSGIServer but never calls monkey.patch_all().
# gevent is cooperative, so a single blocking resolver (the SSRF fetch in importPaste, the
# command-injection subprocess in systemDebug/systemDiagnostics, or a heavy/batched query) freezes
# the whole server until it returns, and every other request queues and times out. A scan then
# appears to "wedge" on every step. Prepending monkey.patch_all() makes those blocking calls yield,
# so one slow request no longer stalls the rest and the server handles concurrent scans.
#
# Build:  docker build -f docker/dvga.Dockerfile -t gradientql-dvga .
# Run:    docker run -d -p 5013:5013 --name dvga gradientql-dvga
FROM dolevf/dvga

# Insert the monkey-patch as the very first line of app.py so it runs before any other import.
RUN sed -i '1ifrom gevent import monkey; monkey.patch_all()' /opt/dvga/app.py

ENV WEB_HOST=0.0.0.0
EXPOSE 5013

# CMD (python app.py) and WORKDIR (/opt/dvga) are inherited from the base image.
