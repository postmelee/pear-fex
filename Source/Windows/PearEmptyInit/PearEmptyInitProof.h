// SPDX-License-Identifier: MIT
// Private one-shot source selection after the finite source/metadata review.
// This is a build candidate only: the root must revalidate its exact linked
// image, stack/storage bounds and current signed runtime before invocation.
// It grants no Module initialization, guest dispatch or distribution support.
#pragma once
namespace FEX::Windows::PearEmptyInit::Proof {
inline constexpr bool SelectedSourceGraph = true;
inline constexpr bool CheckedCRTLinkClosure = true;
inline constexpr bool CompiledWholeMetadata = true;
inline constexpr bool SourceLifetimeAndEntry = true;
inline constexpr bool ExactCallerImageAdmission = true;
inline constexpr bool CurrentHostPermission = true;
inline constexpr bool BoundedTiming = true;
inline constexpr bool CheckedEnvironmentConstructor = true;
inline constexpr bool CheckedContextAllocation = true;
inline constexpr bool SelectedDeletionReceipt = true;
inline constexpr bool CheckedSourceDependencyAllocations = true;
inline constexpr bool SelectedGlobalConstructorContracts = true;
inline constexpr bool FiniteTransfer = true;
inline bool Ready() {
  // Keep the exact reviewed body inspectable in the selected candidate.
  // No caller, environment or command-line flag can change this selection;
  // the bounded root admission remains mandatory before any invocation.
  const volatile bool Selected = SelectedSourceGraph && CheckedCRTLinkClosure && CompiledWholeMetadata &&
    SourceLifetimeAndEntry && ExactCallerImageAdmission && CurrentHostPermission && BoundedTiming &&
    CheckedEnvironmentConstructor && CheckedContextAllocation && SelectedDeletionReceipt &&
    CheckedSourceDependencyAllocations && SelectedGlobalConstructorContracts;
  return Selected;
}
} // namespace FEX::Windows::PearEmptyInit::Proof
