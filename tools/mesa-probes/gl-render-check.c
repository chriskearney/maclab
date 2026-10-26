/* SPDX-License-Identifier: MIT */
/*
 * gl-render-check: a headless OpenGL ES render job that checks every pixel.
 *
 *   gl-render-check SECS [--no-check]
 *
 * Surfaceless EGL, a GLES 3.0 context and a 64x64 RGBA8 framebuffer object:
 * glClear to (32, 64, 96, 255), then one triangle covering the 48x48
 * viewport and scissor at (8, 8) whose fragment shader writes
 * (4x, 4y, 255 if x ^ y is odd, 255) from gl_FragCoord. Reads the whole
 * framebuffer back (into memory filled with 0xa5 first) and compares all 4096
 * pixels with the expected values, allowing 1 in each channel for the
 * float-to-unorm conversion. Repeats for SECS seconds (1..600). One line per
 * run with wrong pixels. The renderer must contain "zink" and "M3", as
 * gpu-heat requires; RENDER_CHECK_RENDERER=TEXT requires TEXT instead (to
 * check this program on another GPU). RENDER_CHECK_RUNS=N stops after N
 * runs (for repeatable command-stream dumps).
 *
 * Exit status: 0 when every run matched, 1 on a mismatch, 2 on an EGL or GL
 * error or the wrong renderer. --no-check skips the comparison (for
 * drm-shim, which executes nothing).
 */
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES3/gl3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SIZE 64
#define VIEW_OFFSET 8
#define VIEW_SIZE 48

#define CHECK(x)                                                               \
   do {                                                                        \
      if (!(x)) {                                                              \
         fprintf(stderr, "gl-render-check: line %d: %s failed (EGL 0x%x, GL " \
                 "0x%x)\n", __LINE__, #x, eglGetError(), glGetError());       \
         exit(2);                                                              \
      }                                                                        \
   } while (0)

static double
now(void)
{
   struct timespec ts;
   clock_gettime(CLOCK_MONOTONIC, &ts);
   return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void
expected(int x, int y, uint8_t px[4])
{
   const bool inside = x >= VIEW_OFFSET && x < VIEW_OFFSET + VIEW_SIZE &&
                       y >= VIEW_OFFSET && y < VIEW_OFFSET + VIEW_SIZE;
   if (inside) {
      px[0] = (x * 4) & 255;
      px[1] = (y * 4) & 255;
      px[2] = ((x ^ y) & 1) ? 255 : 0;
   } else {
      px[0] = 32;
      px[1] = 64;
      px[2] = 96;
   }
   px[3] = 255;
}

static GLuint
compile(GLenum type, const char *src)
{
   GLuint s = glCreateShader(type);
   glShaderSource(s, 1, &src, NULL);
   glCompileShader(s);
   GLint ok = 0;
   glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
   if (!ok) {
      char log[2048] = "";
      glGetShaderInfoLog(s, sizeof(log), NULL, log);
      fprintf(stderr, "gl-render-check: shader compile failed: %s\n", log);
      exit(2);
   }
   return s;
}

static const char *vs_src =
   "#version 300 es\n"
   "void main() {\n"
   "   vec2 p = vec2(float((gl_VertexID << 1) & 2), float(gl_VertexID & 2));\n"
   "   gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);\n"
   "}\n";

static const char *fs_src =
   "#version 300 es\n"
   "precision highp float;\n"
   "precision highp int;\n"
   "out vec4 color;\n"
   "void main() {\n"
   "   ivec2 p = ivec2(gl_FragCoord.xy);\n"
   "   color = vec4(float((p.x * 4) & 255) / 255.0,\n"
   "                float((p.y * 4) & 255) / 255.0,\n"
   "                float((p.x ^ p.y) & 1), 1.0);\n"
   "}\n";

int
main(int argc, char **argv)
{
   const bool check = !(argc == 3 && !strcmp(argv[2], "--no-check"));
   const double secs = (argc == 2 || !check) ? atof(argv[1]) : 0;
   if (!(secs >= 1 && secs <= 600)) {
      fprintf(stderr, "usage: %s SECS (1..600) [--no-check]\n", argv[0]);
      return 2;
   }

   EGLDisplay dpy = eglGetPlatformDisplay(EGL_PLATFORM_SURFACELESS_MESA,
                                          EGL_DEFAULT_DISPLAY, NULL);
   CHECK(dpy != EGL_NO_DISPLAY);
   EGLint maj, min;
   CHECK(eglInitialize(dpy, &maj, &min));
   CHECK(eglBindAPI(EGL_OPENGL_ES_API));
   const EGLint attrs[] = {EGL_CONTEXT_MAJOR_VERSION, 3, EGL_NONE};
   EGLContext ctx =
      eglCreateContext(dpy, EGL_NO_CONFIG_KHR, EGL_NO_CONTEXT, attrs);
   CHECK(ctx != EGL_NO_CONTEXT);
   CHECK(eglMakeCurrent(dpy, EGL_NO_SURFACE, EGL_NO_SURFACE, ctx));

   const char *renderer = (const char *)glGetString(GL_RENDERER);
   printf("Renderer: %s\n", renderer ? renderer : "(none)");
   printf("Version: %s\n", (const char *)glGetString(GL_VERSION));
   const char *want = getenv("RENDER_CHECK_RENDERER");
   if (want && want[0]) {
      CHECK(renderer && strstr(renderer, want));
   } else {
      CHECK(renderer && strstr(renderer, "zink") && strstr(renderer, "M3"));
   }

   GLuint tex, fb;
   glGenTextures(1, &tex);
   glBindTexture(GL_TEXTURE_2D, tex);
   glTexStorage2D(GL_TEXTURE_2D, 1, GL_RGBA8, SIZE, SIZE);
   glGenFramebuffers(1, &fb);
   glBindFramebuffer(GL_FRAMEBUFFER, fb);
   glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
                          tex, 0);
   CHECK(glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE);

   GLuint prog = glCreateProgram();
   glAttachShader(prog, compile(GL_VERTEX_SHADER, vs_src));
   glAttachShader(prog, compile(GL_FRAGMENT_SHADER, fs_src));
   glLinkProgram(prog);
   GLint ok = 0;
   glGetProgramiv(prog, GL_LINK_STATUS, &ok);
   CHECK(ok);
   GLuint vao;
   glGenVertexArrays(1, &vao);
   glBindVertexArray(vao);
   CHECK(glGetError() == GL_NO_ERROR);

   static uint8_t pixels[SIZE * SIZE * 4];
   printf("gl-render-check: %dx%d clear + %dx%d triangle, %.0f s%s\n", SIZE,
          SIZE, VIEW_SIZE, VIEW_SIZE, secs, check ? "" : " (no check)");
   fflush(stdout);
   const char *max_env = getenv("RENDER_CHECK_RUNS");
   const unsigned long max_runs =
      max_env && max_env[0] ? strtoul(max_env, NULL, 10) : 0;
   const double t0 = now();
   double last = t0;
   unsigned long runs = 0, bad_runs = 0;
   while (now() - t0 < secs && (!max_runs || runs < max_runs)) {
      glDisable(GL_SCISSOR_TEST);
      glViewport(0, 0, SIZE, SIZE);
      glClearColor(32 / 255.0f, 64 / 255.0f, 96 / 255.0f, 1.0f);
      glClear(GL_COLOR_BUFFER_BIT);
      glEnable(GL_SCISSOR_TEST);
      glScissor(VIEW_OFFSET, VIEW_OFFSET, VIEW_SIZE, VIEW_SIZE);
      glViewport(VIEW_OFFSET, VIEW_OFFSET, VIEW_SIZE, VIEW_SIZE);
      glUseProgram(prog);
      glDrawArrays(GL_TRIANGLES, 0, 3);
      memset(pixels, 0xa5, sizeof(pixels));
      glReadPixels(0, 0, SIZE, SIZE, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
      CHECK(glGetError() == GL_NO_ERROR);
      ++runs;

      if (check) {
         unsigned wrong = 0;
         int first_x = 0, first_y = 0;
         uint8_t first_got[4] = {0}, first_want[4] = {0};
         for (int y = 0; y < SIZE; ++y) {
            for (int x = 0; x < SIZE; ++x) {
               const uint8_t *got = pixels + (y * SIZE + x) * 4;
               uint8_t want_px[4];
               expected(x, y, want_px);
               bool good = true;
               for (unsigned c = 0; c < 4; ++c)
                  good &= abs((int)got[c] - (int)want_px[c]) <= 1;
               if (!good && wrong++ == 0) {
                  first_x = x;
                  first_y = y;
                  memcpy(first_got, got, 4);
                  memcpy(first_want, want_px, 4);
               }
            }
         }
         if (wrong) {
            ++bad_runs;
            printf("MISMATCH run %lu: %u of %d pixels wrong; first at (%d, %d): "
                   "got %u %u %u %u, want %u %u %u %u\n",
                   runs, wrong, SIZE * SIZE, first_x, first_y, first_got[0],
                   first_got[1], first_got[2], first_got[3], first_want[0],
                   first_want[1], first_want[2], first_want[3]);
            fflush(stdout);
         }
      }
      if (now() - last >= 5.0) {
         last = now();
         printf("progress t=%.1fs runs=%lu wrong=%lu\n", last - t0, runs,
                bad_runs);
         fflush(stdout);
      }
   }

   const double dt = now() - t0;
   if (!check)
      printf("DONE: %lu runs in %.1f s, not checked\n", runs, dt);
   else if (bad_runs)
      printf("FAIL: %lu runs in %.1f s, %lu with wrong pixels\n", runs, dt,
             bad_runs);
   else
      printf("PASS: %lu runs in %.1f s, 0 with wrong pixels\n", runs, dt);

   eglMakeCurrent(dpy, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
   eglDestroyContext(dpy, ctx);
   eglTerminate(dpy);
   return bad_runs ? 1 : 0;
}
