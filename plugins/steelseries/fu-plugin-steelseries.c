/*
 * Copyright (C) 2016 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>

#include "fu-steelseries-device.h"
#include "fu-steelseries-gamepad.h"
#include "fu-steelseries-sonic.h"

static void
fu_plugin_steelseries_init(FuPlugin *plugin)
{
	fu_plugin_add_device_gtype(plugin, FU_TYPE_STEELSERIES_DEVICE);
	fu_plugin_add_device_gtype(plugin, FU_TYPE_STEELSERIES_GAMEPAD);
	fu_plugin_add_device_gtype(plugin, FU_TYPE_STEELSERIES_SONIC);
}

static void
fu_plugin_steelseries_load(FuContext *ctx)
{
	fu_context_add_quirk_key(ctx, "SteelSeriesDeviceKind");
}

void
fu_plugin_init_vfuncs(FuPluginVfuncs *vfuncs)
{
	vfuncs->build_hash = FU_BUILD_HASH;
	vfuncs->load = fu_plugin_steelseries_load;
	vfuncs->init = fu_plugin_steelseries_init;
}
