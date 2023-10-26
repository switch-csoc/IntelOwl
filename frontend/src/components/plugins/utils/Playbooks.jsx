import React from "react";

import { playbookTableColumns } from "./data";
import { pluginsTypes } from "../../../constants/constants";
import PluginWrapper from "./PluginWrapper";

export default function Playbooks() {
  console.debug("Playbooks rendered!");

  const stateSelector = React.useCallback(
    (state) => [
      state.playbooksLoading,
      state.playbooksError,
      state.playbooks,
      state.retrievePlaybooksConfiguration,
    ],
    [],
  );

  return (
    <PluginWrapper
      heading="Playbooks"
      description="Playbooks are designed to be easy to share sequence of running Analyzers/Connectors on a particular kind of observable."
      stateSelector={stateSelector}
      columns={playbookTableColumns}
      type={pluginsTypes.PLAYBOOK}
    />
  );
}
