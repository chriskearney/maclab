/* SPDX-License-Identifier: MIT */
/*
 * vk-render-check: a headless Vulkan render job that checks every pixel.
 *
 *   vk-render-check SECS [--no-check]
 *
 * On the first Apple GPU, renders into a 64x64 RGBA8 image: a render-pass
 * clear to (32, 64, 96, 255), then one triangle covering the 48x48 viewport
 * at (8, 8) whose fragment shader writes (4x, 4y, 255 if x ^ y is odd, 255)
 * from gl_FragCoord. Copies the image to a host buffer (filled with 0xa5
 * before each run) and compares all 4096 pixels with the expected values,
 * allowing 1 in each channel for the float-to-unorm conversion. Repeats for
 * SECS seconds (1..600). One line per run with wrong pixels.
 *
 * Exit status: 0 when every run completed and every pixel matched, 1 on a
 * mismatch, 2 on a Vulkan error, a missing device or a fence timeout (10 s).
 * --no-check skips the comparison (for drm-shim, which executes nothing).
 * RENDER_CHECK_DEVICE=TEXT picks the first device whose name contains TEXT
 * instead of "Apple" (to check this program on another GPU).
 * RENDER_CHECK_RUNS=N stops after N runs (for repeatable command-stream
 * dumps).
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vulkan/vulkan.h>

#include "render-check.frag.h"
#include "render-check.vert.h"

#define SIZE 64u
#define VIEW_OFFSET 8u
#define VIEW_SIZE 48u
#define FENCE_TIMEOUT_NS (10ull * 1000000000ull)

#define VK(x)                                                                  \
   do {                                                                        \
      VkResult r_ = (x);                                                       \
      if (r_ != VK_SUCCESS) {                                                  \
         fprintf(stderr, "vk-render-check: %s failed: %d (line %d)\n", #x,     \
                 r_, __LINE__);                                                \
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
expected(uint32_t x, uint32_t y, uint8_t px[4])
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

static uint32_t
memory_type(VkPhysicalDevice pdev, uint32_t bits, VkMemoryPropertyFlags want)
{
   VkPhysicalDeviceMemoryProperties props;
   vkGetPhysicalDeviceMemoryProperties(pdev, &props);
   for (uint32_t i = 0; i < props.memoryTypeCount; ++i) {
      if ((bits & (1u << i)) &&
          (props.memoryTypes[i].propertyFlags & want) == want)
         return i;
   }
   fprintf(stderr, "vk-render-check: no memory type with flags 0x%x\n", want);
   exit(2);
}

static VkShaderModule
shader(VkDevice dev, const uint32_t *code, size_t size)
{
   const VkShaderModuleCreateInfo info = {
      .sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
      .codeSize = size,
      .pCode = code,
   };
   VkShaderModule module;
   VK(vkCreateShaderModule(dev, &info, NULL, &module));
   return module;
}

int
main(int argc, char **argv)
{
   const bool check = !(argc == 3 && !strcmp(argv[2], "--no-check"));
   const double secs = (argc == 2 || !check) ? atof(argv[1]) : 0;
   if (!(secs >= 1 && secs <= 600)) {
      fprintf(stderr, "usage: %s SECS (1..600) [--no-check]\n", argv[0]);
      return 2;
   }

   const VkApplicationInfo app = {
      .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
      .pApplicationName = "vk-render-check",
      .apiVersion = VK_API_VERSION_1_1,
   };
   const VkInstanceCreateInfo iinfo = {
      .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
      .pApplicationInfo = &app,
   };
   VkInstance inst;
   VK(vkCreateInstance(&iinfo, NULL, &inst));

   uint32_t npdev = 0;
   VK(vkEnumeratePhysicalDevices(inst, &npdev, NULL));
   VkPhysicalDevice pdevs[8];
   npdev = npdev > 8 ? 8 : npdev;
   VK(vkEnumeratePhysicalDevices(inst, &npdev, pdevs));
   const char *want_name = getenv("RENDER_CHECK_DEVICE");
   if (!want_name || !want_name[0])
      want_name = "Apple";
   VkPhysicalDevice pdev = VK_NULL_HANDLE;
   VkPhysicalDeviceProperties props;
   for (uint32_t i = 0; i < npdev && !pdev; ++i) {
      vkGetPhysicalDeviceProperties(pdevs[i], &props);
      if (strstr(props.deviceName, want_name))
         pdev = pdevs[i];
   }
   if (!pdev) {
      fprintf(stderr, "vk-render-check: no %s GPU among %u devices\n",
              want_name, npdev);
      return 2;
   }
   printf("Device: %s (deviceID 0x%x)\n", props.deviceName, props.deviceID);

   uint32_t nq = 0;
   vkGetPhysicalDeviceQueueFamilyProperties(pdev, &nq, NULL);
   VkQueueFamilyProperties qprops[16];
   nq = nq > 16 ? 16 : nq;
   vkGetPhysicalDeviceQueueFamilyProperties(pdev, &nq, qprops);
   uint32_t family = UINT32_MAX;
   for (uint32_t i = 0; i < nq && family == UINT32_MAX; ++i) {
      if (qprops[i].queueFlags & VK_QUEUE_GRAPHICS_BIT)
         family = i;
   }
   if (family == UINT32_MAX) {
      fprintf(stderr, "vk-render-check: no graphics queue\n");
      return 2;
   }

   const float priority = 1.0f;
   const VkDeviceQueueCreateInfo qinfo = {
      .sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
      .queueFamilyIndex = family,
      .queueCount = 1,
      .pQueuePriorities = &priority,
   };
   const VkDeviceCreateInfo dinfo = {
      .sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
      .queueCreateInfoCount = 1,
      .pQueueCreateInfos = &qinfo,
   };
   VkDevice dev;
   VK(vkCreateDevice(pdev, &dinfo, NULL, &dev));
   VkQueue queue;
   vkGetDeviceQueue(dev, family, 0, &queue);

   /* The colour target. */
   const VkImageCreateInfo image_info = {
      .sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
      .imageType = VK_IMAGE_TYPE_2D,
      .format = VK_FORMAT_R8G8B8A8_UNORM,
      .extent = {SIZE, SIZE, 1},
      .mipLevels = 1,
      .arrayLayers = 1,
      .samples = VK_SAMPLE_COUNT_1_BIT,
      .tiling = VK_IMAGE_TILING_OPTIMAL,
      .usage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT |
               VK_IMAGE_USAGE_TRANSFER_SRC_BIT,
      .sharingMode = VK_SHARING_MODE_EXCLUSIVE,
      .initialLayout = VK_IMAGE_LAYOUT_UNDEFINED,
   };
   VkImage image;
   VK(vkCreateImage(dev, &image_info, NULL, &image));
   VkMemoryRequirements req;
   vkGetImageMemoryRequirements(dev, image, &req);
   const VkMemoryAllocateInfo image_alloc = {
      .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
      .allocationSize = req.size,
      .memoryTypeIndex = memory_type(pdev, req.memoryTypeBits,
                                     VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT),
   };
   VkDeviceMemory image_mem;
   VK(vkAllocateMemory(dev, &image_alloc, NULL, &image_mem));
   VK(vkBindImageMemory(dev, image, image_mem, 0));
   const VkImageViewCreateInfo view_info = {
      .sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO,
      .image = image,
      .viewType = VK_IMAGE_VIEW_TYPE_2D,
      .format = VK_FORMAT_R8G8B8A8_UNORM,
      .subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1},
   };
   VkImageView view;
   VK(vkCreateImageView(dev, &view_info, NULL, &view));

   /* The host buffer the image is copied to. */
   const VkBufferCreateInfo buf_info = {
      .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
      .size = SIZE * SIZE * 4,
      .usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT,
      .sharingMode = VK_SHARING_MODE_EXCLUSIVE,
   };
   VkBuffer buf;
   VK(vkCreateBuffer(dev, &buf_info, NULL, &buf));
   vkGetBufferMemoryRequirements(dev, buf, &req);
   const VkMemoryAllocateInfo buf_alloc = {
      .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
      .allocationSize = req.size,
      .memoryTypeIndex = memory_type(pdev, req.memoryTypeBits,
                                     VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
                                        VK_MEMORY_PROPERTY_HOST_COHERENT_BIT),
   };
   VkDeviceMemory buf_mem;
   VK(vkAllocateMemory(dev, &buf_alloc, NULL, &buf_mem));
   VK(vkBindBufferMemory(dev, buf, buf_mem, 0));
   uint8_t *pixels;
   VK(vkMapMemory(dev, buf_mem, 0, VK_WHOLE_SIZE, 0, (void **)&pixels));

   const VkAttachmentDescription attachment = {
      .format = VK_FORMAT_R8G8B8A8_UNORM,
      .samples = VK_SAMPLE_COUNT_1_BIT,
      .loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR,
      .storeOp = VK_ATTACHMENT_STORE_OP_STORE,
      .stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE,
      .stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE,
      .initialLayout = VK_IMAGE_LAYOUT_UNDEFINED,
      .finalLayout = VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
   };
   const VkAttachmentReference color_ref = {
      0, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL,
   };
   const VkSubpassDescription subpass = {
      .pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS,
      .colorAttachmentCount = 1,
      .pColorAttachments = &color_ref,
   };
   const VkSubpassDependency dependency = {
      .srcSubpass = 0,
      .dstSubpass = VK_SUBPASS_EXTERNAL,
      .srcStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT,
      .dstStageMask = VK_PIPELINE_STAGE_TRANSFER_BIT,
      .srcAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT,
      .dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT,
   };
   const VkRenderPassCreateInfo rp_info = {
      .sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO,
      .attachmentCount = 1,
      .pAttachments = &attachment,
      .subpassCount = 1,
      .pSubpasses = &subpass,
      .dependencyCount = 1,
      .pDependencies = &dependency,
   };
   VkRenderPass pass;
   VK(vkCreateRenderPass(dev, &rp_info, NULL, &pass));
   const VkFramebufferCreateInfo fb_info = {
      .sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO,
      .renderPass = pass,
      .attachmentCount = 1,
      .pAttachments = &view,
      .width = SIZE,
      .height = SIZE,
      .layers = 1,
   };
   VkFramebuffer fb;
   VK(vkCreateFramebuffer(dev, &fb_info, NULL, &fb));

   const VkShaderModule vs =
      shader(dev, render_check_vert, sizeof(render_check_vert));
   const VkShaderModule fs =
      shader(dev, render_check_frag, sizeof(render_check_frag));
   const VkPipelineShaderStageCreateInfo stages[] = {
      {.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
       .stage = VK_SHADER_STAGE_VERTEX_BIT, .module = vs, .pName = "main"},
      {.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
       .stage = VK_SHADER_STAGE_FRAGMENT_BIT, .module = fs, .pName = "main"},
   };
   const VkPipelineVertexInputStateCreateInfo vertex_input = {
      .sType = VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO,
   };
   const VkPipelineInputAssemblyStateCreateInfo assembly = {
      .sType = VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO,
      .topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST,
   };
   const VkViewport viewport = {
      VIEW_OFFSET, VIEW_OFFSET, VIEW_SIZE, VIEW_SIZE, 0.0f, 1.0f,
   };
   const VkRect2D scissor = {{VIEW_OFFSET, VIEW_OFFSET}, {VIEW_SIZE, VIEW_SIZE}};
   const VkPipelineViewportStateCreateInfo viewport_state = {
      .sType = VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO,
      .viewportCount = 1,
      .pViewports = &viewport,
      .scissorCount = 1,
      .pScissors = &scissor,
   };
   const VkPipelineRasterizationStateCreateInfo raster = {
      .sType = VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO,
      .polygonMode = VK_POLYGON_MODE_FILL,
      .cullMode = VK_CULL_MODE_NONE,
      .frontFace = VK_FRONT_FACE_COUNTER_CLOCKWISE,
      .lineWidth = 1.0f,
   };
   const VkPipelineMultisampleStateCreateInfo multisample = {
      .sType = VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO,
      .rasterizationSamples = VK_SAMPLE_COUNT_1_BIT,
   };
   const VkPipelineColorBlendAttachmentState blend_attachment = {
      .colorWriteMask = VK_COLOR_COMPONENT_R_BIT | VK_COLOR_COMPONENT_G_BIT |
                        VK_COLOR_COMPONENT_B_BIT | VK_COLOR_COMPONENT_A_BIT,
   };
   const VkPipelineColorBlendStateCreateInfo blend = {
      .sType = VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO,
      .attachmentCount = 1,
      .pAttachments = &blend_attachment,
   };
   const VkPipelineLayoutCreateInfo pl_info = {
      .sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
   };
   VkPipelineLayout layout;
   VK(vkCreatePipelineLayout(dev, &pl_info, NULL, &layout));
   const VkGraphicsPipelineCreateInfo gp_info = {
      .sType = VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO,
      .stageCount = 2,
      .pStages = stages,
      .pVertexInputState = &vertex_input,
      .pInputAssemblyState = &assembly,
      .pViewportState = &viewport_state,
      .pRasterizationState = &raster,
      .pMultisampleState = &multisample,
      .pColorBlendState = &blend,
      .layout = layout,
      .renderPass = pass,
      .subpass = 0,
   };
   VkPipeline pipeline;
   VK(vkCreateGraphicsPipelines(dev, VK_NULL_HANDLE, 1, &gp_info, NULL,
                                &pipeline));

   const VkCommandPoolCreateInfo pool_info = {
      .sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
      .queueFamilyIndex = family,
   };
   VkCommandPool pool;
   VK(vkCreateCommandPool(dev, &pool_info, NULL, &pool));
   const VkCommandBufferAllocateInfo cb_info = {
      .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
      .commandPool = pool,
      .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
      .commandBufferCount = 1,
   };
   VkCommandBuffer cmd;
   VK(vkAllocateCommandBuffers(dev, &cb_info, &cmd));
   const VkCommandBufferBeginInfo begin = {
      .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
   };
   VK(vkBeginCommandBuffer(cmd, &begin));
   const VkClearValue clear = {
      .color = {.float32 = {32 / 255.0f, 64 / 255.0f, 96 / 255.0f, 1.0f}},
   };
   const VkRenderPassBeginInfo rp_begin = {
      .sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO,
      .renderPass = pass,
      .framebuffer = fb,
      .renderArea = {{0, 0}, {SIZE, SIZE}},
      .clearValueCount = 1,
      .pClearValues = &clear,
   };
   vkCmdBeginRenderPass(cmd, &rp_begin, VK_SUBPASS_CONTENTS_INLINE);
   vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, pipeline);
   vkCmdDraw(cmd, 3, 1, 0, 0);
   vkCmdEndRenderPass(cmd);
   const VkBufferImageCopy region = {
      .imageSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 0, 1},
      .imageExtent = {SIZE, SIZE, 1},
   };
   vkCmdCopyImageToBuffer(cmd, image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                          buf, 1, &region);
   const VkMemoryBarrier to_host = {
      .sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER,
      .srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT,
      .dstAccessMask = VK_ACCESS_HOST_READ_BIT,
   };
   vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TRANSFER_BIT,
                        VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &to_host, 0, NULL, 0,
                        NULL);
   VK(vkEndCommandBuffer(cmd));

   const VkFenceCreateInfo fence_info = {
      .sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO,
   };
   VkFence fence;
   VK(vkCreateFence(dev, &fence_info, NULL, &fence));
   const VkSubmitInfo submit = {
      .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
      .commandBufferCount = 1,
      .pCommandBuffers = &cmd,
   };

   printf("vk-render-check: %ux%u clear + %ux%u triangle, %.0f s%s\n", SIZE,
          SIZE, VIEW_SIZE, VIEW_SIZE, secs, check ? "" : " (no check)");
   fflush(stdout);
   const char *max_env = getenv("RENDER_CHECK_RUNS");
   const unsigned long max_runs =
      max_env && max_env[0] ? strtoul(max_env, NULL, 10) : 0;
   const double t0 = now();
   double last = t0;
   unsigned long runs = 0, bad_runs = 0;
   while (now() - t0 < secs && (!max_runs || runs < max_runs)) {
      memset(pixels, 0xa5, SIZE * SIZE * 4);
      VK(vkQueueSubmit(queue, 1, &submit, fence));
      VkResult r = vkWaitForFences(dev, 1, &fence, VK_TRUE, FENCE_TIMEOUT_NS);
      if (r != VK_SUCCESS) {
         fprintf(stderr, "vk-render-check: run %lu did not complete: %d\n",
                 runs, r);
         return 2;
      }
      VK(vkResetFences(dev, 1, &fence));
      ++runs;

      if (check) {
         unsigned wrong = 0, first_x = 0, first_y = 0;
         uint8_t first_got[4] = {0}, first_want[4] = {0};
         for (uint32_t y = 0; y < SIZE; ++y) {
            for (uint32_t x = 0; x < SIZE; ++x) {
               const uint8_t *got = pixels + (y * SIZE + x) * 4;
               uint8_t want[4];
               expected(x, y, want);
               bool ok = true;
               for (unsigned c = 0; c < 4; ++c)
                  ok &= abs((int)got[c] - (int)want[c]) <= 1;
               if (!ok && wrong++ == 0) {
                  first_x = x;
                  first_y = y;
                  memcpy(first_got, got, 4);
                  memcpy(first_want, want, 4);
               }
            }
         }
         if (wrong) {
            ++bad_runs;
            printf("MISMATCH run %lu: %u of %u pixels wrong; first at (%u, %u): "
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

   vkDestroyFence(dev, fence, NULL);
   vkDestroyCommandPool(dev, pool, NULL);
   vkDestroyPipeline(dev, pipeline, NULL);
   vkDestroyPipelineLayout(dev, layout, NULL);
   vkDestroyShaderModule(dev, fs, NULL);
   vkDestroyShaderModule(dev, vs, NULL);
   vkDestroyFramebuffer(dev, fb, NULL);
   vkDestroyRenderPass(dev, pass, NULL);
   vkUnmapMemory(dev, buf_mem);
   vkDestroyBuffer(dev, buf, NULL);
   vkFreeMemory(dev, buf_mem, NULL);
   vkDestroyImageView(dev, view, NULL);
   vkDestroyImage(dev, image, NULL);
   vkFreeMemory(dev, image_mem, NULL);
   vkDestroyDevice(dev, NULL);
   vkDestroyInstance(inst, NULL);
   return bad_runs ? 1 : 0;
}
