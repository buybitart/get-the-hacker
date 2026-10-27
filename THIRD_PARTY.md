# Third-party Code

GTH code and documentation use GPL-2.0-only. See LICENSE and AUTHORS.
Scapy 2.6.1 runtime source is bundled in vendor/scapy/.
Its license is vendor/scapy-2.6.1.dist-info/LICENSE.
Its version and author metadata are kept beside that license.
Scapy copyright and SPDX notices stay in its source files.
GTH does not claim authorship of Scapy.

The subset keeps the conservative GTH import closure.
It includes imports inside functions and all platform branches.
Unused protocol add-ons, tool scripts, and the test CLI are excluded.
The libs/test_pyx.py file is a Scapy runtime capability probe.
It is not a project test or test dataset.
Included Scapy modules have their full unmodified Python source.
No binary Scapy library is shipped.

ReportLab is optional. It is not bundled.
GTH uses its portable PDF writer when ReportLab is absent.
Local system fonts are not redistributed by this project.
